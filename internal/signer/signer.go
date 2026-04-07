package signer

import (
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"strconv"
	"time"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/tss"

	"github.com/alexarsh/mpc-signer/internal/transport"
)

// Signature holds an ECDSA signature.
type Signature struct {
	R []byte `json:"r"` // 32 bytes
	S []byte `json:"s"` // 32 bytes
	V int    `json:"v"` // recovery ID (0 or 1)
}

// InitMessage is sent from the initiator to tell the co-signer to join a signing session.
type InitMessage struct {
	SessionID string   `json:"session_id"`
	KeyID     string   `json:"key_id"`
	Digest    string   `json:"digest"`  // hex-encoded
	Signers   []string `json:"signers"` // e.g. ["s1", "s2"] — the 2 parties signing
}

// WireMessage is the serializable form of a tss-lib protocol message.
type WireMessage struct {
	FromID      string `json:"from_id"`
	IsBroadcast bool   `json:"is_broadcast"`
	Bytes       []byte `json:"bytes"`
}

// Handler manages the MPC signing protocol.
type Handler struct {
	nodeID    string
	transport *transport.Transport
}

// NewHandler creates a new signing handler.
func NewHandler(nodeID string, t *transport.Transport) *Handler {
	return &Handler{
		nodeID:    nodeID,
		transport: t,
	}
}

// Run initiates a 2-of-3 signing session — sends sign_init to the co-signer, then runs the protocol.
func (h *Handler) Run(sessionID string, keyID string, digest []byte, saveData *keygen.LocalPartySaveData, signers []string) (*Signature, error) {
	log.Printf("[%s] initiating signing session=%s signers=%v", h.nodeID, sessionID, signers)

	// Determine the co-signer (the other party in the signers list)
	coSigner := ""
	for _, s := range signers {
		if s != h.nodeID {
			coSigner = s
			break
		}
	}
	if coSigner == "" {
		return nil, fmt.Errorf("no co-signer found in signers list %v for node %s", signers, h.nodeID)
	}

	initPayload, _ := json.Marshal(InitMessage{
		SessionID: sessionID,
		KeyID:     keyID,
		Digest:    fmt.Sprintf("%x", digest),
		Signers:   signers,
	})
	err := h.transport.Send(&transport.Message{
		Type:      "sign_init",
		SessionID: sessionID,
		To:        coSigner, // send only to the co-signer
		Payload:   initPayload,
	})
	if err != nil {
		return nil, fmt.Errorf("send sign_init: %w", err)
	}

	return h.runProtocol(sessionID, digest, saveData, signers, nil)
}

// Subscribe pre-subscribes to a signing session so messages are buffered
// while the caller prepares (loads tss data, etc.). Must be called before
// the initiator starts the protocol to avoid missing messages.
func (h *Handler) Subscribe(sessionID string) chan *transport.Message {
	return h.transport.Subscribe(sessionID)
}

// Join is called on the co-signer side when it receives a sign_init message.
// msgCh is a pre-subscribed channel from Subscribe() — this avoids a race
// where the initiator sends protocol messages before the joiner has subscribed.
func (h *Handler) Join(sessionID string, digest []byte, saveData *keygen.LocalPartySaveData, signers []string, msgCh chan *transport.Message) (*Signature, error) {
	log.Printf("[%s] joining signing session=%s signers=%v", h.nodeID, sessionID, signers)
	return h.runProtocol(sessionID, digest, saveData, signers, msgCh)
}

// runProtocol executes the GG20 signing protocol between the 2 specified signers.
// If msgCh is nil, it subscribes internally. If provided, it uses the pre-subscribed channel.
func (h *Handler) runProtocol(sessionID string, digest []byte, saveData *keygen.LocalPartySaveData, signers []string, msgCh chan *transport.Message) (*Signature, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("digest must be 32 bytes, got %d", len(digest))
	}
	if len(signers) != 2 {
		return nil, fmt.Errorf("exactly 2 signers required for 2-of-3 threshold, got %d", len(signers))
	}

	if msgCh == nil {
		msgCh = h.transport.Subscribe(sessionID)
	}
	defer h.transport.Unsubscribe(sessionID)

	// Build party IDs ONLY for the 2 signing parties.
	// Keys must match those used during DKG (s1=1, s2=2, s3=3).
	partyIDs := make(tss.UnSortedPartyIDs, len(signers))
	for i, id := range signers {
		key := new(big.Int).SetInt64(nodeIndex(id))
		partyIDs[i] = tss.NewPartyID(id, id, key)
	}
	sortedIDs := tss.SortPartyIDs(partyIDs)

	var thisParty *tss.PartyID
	for _, pid := range sortedIDs {
		if pid.Id == h.nodeID {
			thisParty = pid
			break
		}
	}
	if thisParty == nil {
		return nil, fmt.Errorf("node %s not found in signers %v", h.nodeID, signers)
	}

	partyIDMap := make(map[string]*tss.PartyID)
	for _, pid := range sortedIDs {
		partyIDMap[pid.Id] = pid
	}

	ctx := tss.NewPeerContext(sortedIDs)
	// 2 signers, threshold=1 (t+1=2 needed, which is what we have)
	params := tss.NewParameters(tss.S256(), ctx, thisParty, len(signers), len(signers)-1)

	outCh := make(chan tss.Message, 100)
	endCh := make(chan common.SignatureData, 1)

	digestInt := new(big.Int).SetBytes(digest)

	party := signing.NewLocalParty(digestInt, params, *saveData, outCh, endCh)

	errCh := make(chan error, 1)
	go func() {
		if err := party.Start(); err != nil {
			errCh <- fmt.Errorf("start signing: %w", err)
		}
	}()

	timeout := time.After(30 * time.Second)
	for {
		select {
		case err := <-errCh:
			return nil, err

		case msg := <-outCh:
			wireBytes, routing, err := msg.WireBytes()
			if err != nil {
				return nil, fmt.Errorf("get wire bytes: %w", err)
			}

			wireMsg := WireMessage{
				FromID:      h.nodeID,
				IsBroadcast: routing.IsBroadcast,
				Bytes:       wireBytes,
			}

			payload, err := json.Marshal(wireMsg)
			if err != nil {
				return nil, fmt.Errorf("marshal wire message: %w", err)
			}

			wsMsg := &transport.Message{
				Type:      "sign",
				SessionID: sessionID,
				From:      h.nodeID,
				Payload:   payload,
			}

			// For 2-party signing, send directly to the co-signer
			// (avoid broadcasting to non-participating nodes)
			if routing.IsBroadcast {
				for _, pid := range sortedIDs {
					if pid.Id != h.nodeID {
						wsMsg.To = pid.Id
					}
				}
			} else if len(routing.To) > 0 {
				wsMsg.To = routing.To[0].Id
			}

			if err := h.transport.Send(wsMsg); err != nil {
				return nil, fmt.Errorf("send tss message: %w", err)
			}

		case wsMsg := <-msgCh:
			if wsMsg.Type != "sign" {
				continue
			}

			var wireMsg WireMessage
			if err := json.Unmarshal(wsMsg.Payload, &wireMsg); err != nil {
				log.Printf("[%s] failed to unmarshal wire message: %v", h.nodeID, err)
				continue
			}

			fromParty, ok := partyIDMap[wireMsg.FromID]
			if !ok {
				log.Printf("[%s] unknown sender: %s", h.nodeID, wireMsg.FromID)
				continue
			}

			okUpdate, tssErr := party.UpdateFromBytes(wireMsg.Bytes, fromParty, wireMsg.IsBroadcast)
			if tssErr != nil {
				return nil, fmt.Errorf("update party: %v", tssErr)
			}
			if !okUpdate {
				log.Printf("[%s] party update returned false", h.nodeID)
			}

		case sigData := <-endCh: //nolint:govet // tss-lib SignatureData contains protobuf mutex, safe to copy once
			log.Printf("[%s] signing complete!", h.nodeID)
			return &Signature{
				R: padTo32(sigData.GetR()),
				S: padTo32(sigData.GetS()),
				V: int(sigData.GetSignatureRecovery()[0]),
			}, nil

		case <-timeout:
			return nil, fmt.Errorf("signing timed out after 30 seconds")
		}
	}
}

// nodeIndex extracts the numeric index from a node ID like "s1" → 1, "s2" → 2, "s3" → 3.
// These must match the keys used during DKG for Lagrange interpolation to work correctly.
func nodeIndex(id string) int64 {
	if len(id) < 2 {
		return 0
	}
	n, _ := strconv.ParseInt(id[1:], 10, 64)
	return n
}

func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}
