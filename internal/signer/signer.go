package signer

import (
	"encoding/json"
	"fmt"
	"log"
	"math/big"
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

// InitMessage is sent from the initiator to tell the peer to join a signing session.
type InitMessage struct {
	SessionID string `json:"session_id"`
	KeyID     string `json:"key_id"`
	Digest    string `json:"digest"` // hex-encoded
	Threshold int    `json:"threshold"`
	Parties   int    `json:"parties"`
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

// Run initiates a signing session — sends sign_init to the peer, then runs the protocol.
func (h *Handler) Run(sessionID string, keyID string, digest []byte, saveData *keygen.LocalPartySaveData, parties int, threshold int) (*Signature, error) {
	log.Printf("[%s] initiating signing session=%s", h.nodeID, sessionID)

	initPayload, _ := json.Marshal(InitMessage{
		SessionID: sessionID,
		KeyID:     keyID,
		Digest:    fmt.Sprintf("%x", digest),
		Threshold: threshold,
		Parties:   parties,
	})
	err := h.transport.Send(&transport.Message{
		Type:      "sign_init",
		SessionID: sessionID,
		Payload:   initPayload,
	})
	if err != nil {
		return nil, fmt.Errorf("send sign_init: %w", err)
	}

	return h.runProtocol(sessionID, digest, saveData, parties, threshold)
}

// Join is called on the peer side when it receives a sign_init message.
func (h *Handler) Join(sessionID string, digest []byte, saveData *keygen.LocalPartySaveData, parties int, threshold int) (*Signature, error) {
	log.Printf("[%s] joining signing session=%s", h.nodeID, sessionID)
	return h.runProtocol(sessionID, digest, saveData, parties, threshold)
}

// runProtocol executes the GG20 signing protocol.
func (h *Handler) runProtocol(sessionID string, digest []byte, shareData *keygen.LocalPartySaveData, parties int, threshold int) (*Signature, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("digest must be 32 bytes, got %d", len(digest))
	}

	msgCh := h.transport.Subscribe(sessionID)
	defer h.transport.Unsubscribe(sessionID)

	// Set up party IDs (must match DKG)
	partyIDs := make(tss.UnSortedPartyIDs, parties)
	for i := 0; i < parties; i++ {
		id := fmt.Sprintf("s%d", i+1)
		key := new(big.Int).SetInt64(int64(i + 1))
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
		return nil, fmt.Errorf("node %s not found in party IDs", h.nodeID)
	}

	partyIDMap := make(map[string]*tss.PartyID)
	for _, pid := range sortedIDs {
		partyIDMap[pid.Id] = pid
	}

	ctx := tss.NewPeerContext(sortedIDs)
	params := tss.NewParameters(tss.S256(), ctx, thisParty, parties, threshold-1)

	outCh := make(chan tss.Message, 100)
	endCh := make(chan common.SignatureData, 1)

	digestInt := new(big.Int).SetBytes(digest)

	party := signing.NewLocalParty(digestInt, params, *shareData, outCh, endCh)

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

			if routing.IsBroadcast {
				wsMsg.To = "all"
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

func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}
