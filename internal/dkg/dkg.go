package dkg

import (
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"

	"github.com/alexarsh/mpc-signer/internal/transport"
)

// Result holds the output of a successful DKG.
type Result struct {
	Share     []byte // this node's private key share (secret)
	PublicKey []byte // combined public key (uncompressed, 65 bytes with 0x04 prefix)
	ChainCode []byte // BIP32 chain code (32 bytes)
}

// InitMessage is sent from the initiator to tell the peer to join a DKG session.
type InitMessage struct {
	SessionID string `json:"session_id"`
	KeyID     string `json:"key_id"`
	Path      string `json:"path"`
	Threshold int    `json:"threshold"`
	Parties   int    `json:"parties"`
}

// WireMessage is the serializable form of a tss-lib protocol message.
type WireMessage struct {
	FromID      string `json:"from_id"`
	IsBroadcast bool   `json:"is_broadcast"`
	Bytes       []byte `json:"bytes"`
}

// Handler manages the DKG protocol.
type Handler struct {
	nodeID    string
	transport *transport.Transport
}

// NewHandler creates a new DKG handler.
func NewHandler(nodeID string, t *transport.Transport) *Handler {
	return &Handler{
		nodeID:    nodeID,
		transport: t,
	}
}

// Run executes the DKG protocol. The initiator calls this, which tells the peer to join.
func (h *Handler) Run(sessionID, keyID string, threshold, parties int) (*Result, error) {
	log.Printf("[%s] initiating DKG session=%s threshold=%d parties=%d", h.nodeID, sessionID, threshold, parties)

	// Tell the peer to join this DKG session
	initPayload, _ := json.Marshal(InitMessage{
		SessionID: sessionID,
		KeyID:     keyID,
		Threshold: threshold,
		Parties:   parties,
	})
	err := h.transport.Send(&transport.Message{
		Type:      "dkg_init",
		SessionID: sessionID,
		Payload:   initPayload,
	})
	if err != nil {
		return nil, fmt.Errorf("send dkg_init: %w", err)
	}

	return h.runProtocol(sessionID, threshold, parties)
}

// Join is called on the peer side when it receives a dkg_init message.
func (h *Handler) Join(sessionID string, threshold, parties int) (*Result, error) {
	log.Printf("[%s] joining DKG session=%s threshold=%d parties=%d", h.nodeID, sessionID, threshold, parties)
	return h.runProtocol(sessionID, threshold, parties)
}

// runProtocol runs the actual tss-lib keygen protocol (used by both initiator and joiner).
func (h *Handler) runProtocol(sessionID string, threshold, parties int) (*Result, error) {
	// Subscribe to messages for this session
	msgCh := h.transport.Subscribe(sessionID)
	defer h.transport.Unsubscribe(sessionID)

	// Set up party IDs
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
	endCh := make(chan keygen.LocalPartySaveData, 1)

	log.Printf("[%s] generating safe primes (this takes ~1 min)...", h.nodeID)
	preParams, err := keygen.GeneratePreParams(3 * time.Minute)
	if err != nil {
		return nil, fmt.Errorf("generate pre-params: %w", err)
	}
	log.Printf("[%s] safe primes ready, starting keygen protocol", h.nodeID)

	party := keygen.NewLocalParty(params, outCh, endCh, *preParams)

	errCh := make(chan error, 1)
	go func() {
		if err := party.Start(); err != nil {
			errCh <- fmt.Errorf("start keygen: %w", err)
		}
	}()

	timeout := time.After(10 * time.Minute)
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
				Type:      "dkg",
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
			if wsMsg.Type != "dkg" {
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

		case saveData := <-endCh:
			log.Printf("[%s] DKG complete!", h.nodeID)
			return extractResult(&saveData)

		case <-timeout:
			return nil, fmt.Errorf("DKG timed out after 10 minutes")
		}
	}
}

func extractResult(data *keygen.LocalPartySaveData) (*Result, error) {
	shareBytes := data.Xi.Bytes()

	pubX := data.ECDSAPub.X()
	pubY := data.ECDSAPub.Y()
	pubKey := elliptic.Marshal(tss.S256(), pubX, pubY)

	// Chain code must be identical on both nodes for BIP32 derivation to match.
	// Derive deterministically from the combined public key using HMAC-SHA256.
	// Both nodes have the same public key, so they'll get the same chain code.
	mac := hmac.New(sha256.New, []byte("mpc-chain-code"))
	mac.Write(pubKey)
	chainCode := mac.Sum(nil) // 32 bytes

	return &Result{
		Share:     shareBytes,
		PublicKey: pubKey,
		ChainCode: chainCode,
	}, nil
}
