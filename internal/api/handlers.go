package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/gin-gonic/gin"

	"github.com/alexarsh/mpc-signer/internal/derivation"
	"github.com/alexarsh/mpc-signer/internal/dkg"
	"github.com/alexarsh/mpc-signer/internal/keystore"
	"github.com/alexarsh/mpc-signer/internal/signer"
	"github.com/alexarsh/mpc-signer/internal/transport"
	"github.com/alexarsh/mpc-signer/internal/tron"
)

// Server is the REST API server for an MPC node.
type Server struct {
	nodeID    string
	store     *keystore.Store
	transport *transport.Transport
	dkg       *dkg.Handler
	signer    *signer.Handler
}

// NewServer creates a new API server.
func NewServer(nodeID string, store *keystore.Store, t *transport.Transport) *Server {
	return &Server{
		nodeID:    nodeID,
		store:     store,
		transport: t,
		dkg:       dkg.NewHandler(nodeID, t),
		signer:    signer.NewHandler(nodeID, t),
	}
}

// RegisterRoutes sets up the gin routes.
func (s *Server) RegisterRoutes(r *gin.Engine) {
	r.GET("/health", s.healthCheck)
	r.POST("/mpc/keygen", s.keygen)
	r.POST("/mpc/derive-child", s.deriveChild)
	r.POST("/mpc/sign", s.sign)
	r.POST("/wallet/validate-address", s.validateAddress)
}

// StartProtocolListener listens for incoming protocol messages and auto-joins DKG/signing.
// Must be called after the transport is connected.
func (s *Server) StartProtocolListener() {
	go func() {
		for msg := range s.transport.Receive() {
			switch msg.Type {
			case "dkg_init":
				go s.handleDKGInit(msg)
			case "sign_init":
				go s.handleSignInit(msg)
			default:
				log.Printf("[%s] unhandled message type: %s", s.nodeID, msg.Type)
			}
		}
	}()
}

func (s *Server) handleDKGInit(msg *transport.Message) {
	var init dkg.InitMessage
	if err := json.Unmarshal(msg.Payload, &init); err != nil {
		log.Printf("[%s] failed to parse dkg_init: %v", s.nodeID, err)
		return
	}

	log.Printf("[%s] received dkg_init: session=%s threshold=%d parties=%d",
		s.nodeID, init.SessionID, init.Threshold, init.Parties)

	result, err := s.dkg.Join(init.SessionID, init.Threshold, init.Parties)
	if err != nil {
		log.Printf("[%s] DKG join failed: %v", s.nodeID, err)
		return
	}

	// Store our share
	share := &keystore.ShareData{
		Share:     result.Share,
		PublicKey: result.PublicKey,
		ChainCode: result.ChainCode,
	}
	meta := &keystore.Metadata{
		KeyID:     init.KeyID,
		Path:      "",
		Threshold: init.Threshold,
		Parties:   init.Parties,
		CreatedAt: time.Now().UTC(),
	}

	if err := s.store.Save(init.KeyID, share, meta); err != nil {
		log.Printf("[%s] failed to save key share: %v", s.nodeID, err)
		return
	}

	// Save full tss-lib save data for signing
	tssDataBytes, err := json.Marshal(result.SaveData)
	if err != nil {
		log.Printf("[%s] failed to marshal tss save data: %v", s.nodeID, err)
		return
	}
	if err := s.store.SaveTSSData(init.KeyID, tssDataBytes); err != nil {
		log.Printf("[%s] failed to save tss data: %v", s.nodeID, err)
		return
	}

	address, _ := tron.AddressFromPublicKey(result.PublicKey)
	log.Printf("[%s] DKG complete! key=%s address=%s", s.nodeID, init.KeyID, address)
}

func (s *Server) handleSignInit(msg *transport.Message) {
	var init signer.InitMessage
	if err := json.Unmarshal(msg.Payload, &init); err != nil {
		log.Printf("[%s] failed to parse sign_init: %v", s.nodeID, err)
		return
	}

	log.Printf("[%s] received sign_init: session=%s key=%s signers=%v", s.nodeID, init.SessionID, init.KeyID, init.Signers)

	// Subscribe EARLY to buffer protocol messages while we load tss data.
	// Without this, the initiator may send messages before we're ready,
	// causing them to land in the default channel and be lost.
	msgCh := s.signer.Subscribe(init.SessionID)

	// Load tss-lib save data
	saveData, err := s.loadTSSData(init.KeyID)
	if err != nil {
		s.transport.Unsubscribe(init.SessionID)
		log.Printf("[%s] failed to load tss data for signing: %v", s.nodeID, err)
		return
	}

	digest, err := hex.DecodeString(init.Digest)
	if err != nil {
		s.transport.Unsubscribe(init.SessionID)
		log.Printf("[%s] failed to decode digest: %v", s.nodeID, err)
		return
	}

	sig, err := s.signer.Join(init.SessionID, digest, saveData, init.Signers, msgCh)
	if err != nil {
		log.Printf("[%s] signing join failed: %v", s.nodeID, err)
		return
	}

	log.Printf("[%s] signing complete! key=%s r=%x", s.nodeID, init.KeyID, sig.R)
}

func (s *Server) loadTSSData(keyID string) (*keygen.LocalPartySaveData, error) {
	tssBytes, err := s.store.LoadTSSData(keyID)
	if err != nil {
		return nil, err
	}

	var saveData keygen.LocalPartySaveData
	if err := json.Unmarshal(tssBytes, &saveData); err != nil {
		return nil, fmt.Errorf("unmarshal tss data: %w", err)
	}

	return &saveData, nil
}

// --- Request / Response types ---

type KeygenRequest struct {
	KeyID     string `json:"key_id" binding:"required"`
	Path      string `json:"path" binding:"required"`
	Threshold int    `json:"threshold" binding:"required"`
	Parties   int    `json:"parties" binding:"required"`
}

type KeygenResponse struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"` // hex
	ChainCode string `json:"chain_code"` // hex
	Address   string `json:"address"`    // TRON address
}

type DeriveChildRequest struct {
	MasterKeyID string `json:"master_key_id" binding:"required"`
	Path        string `json:"path" binding:"required"` // e.g. "0/42"
}

type DeriveChildResponse struct {
	ChildKeyID string `json:"child_key_id"`
	PublicKey  string `json:"public_key"` // hex
	ChainCode string `json:"chain_code"` // hex
	Address   string `json:"address"`    // TRON address
	Path      string `json:"path"`
}

type SignRequest struct {
	KeyID   string   `json:"key_id" binding:"required"`
	Digest  string   `json:"digest" binding:"required"` // hex-encoded 32-byte SHA256
	Signers []string `json:"signers"`                   // optional: which 2 nodes sign, e.g. ["s1", "s2"]
}

type SignResponse struct {
	R       string   `json:"r"`       // hex
	S       string   `json:"s"`       // hex
	V       int      `json:"v"`       // recovery ID
	Signers []string `json:"signers"` // which 2 nodes signed
}

type ValidateAddressRequest struct {
	Address string `json:"address" binding:"required"`
}

type ValidateAddressResponse struct {
	Address     string `json:"address"`
	Valid       bool   `json:"valid"`
	FormatValid bool   `json:"format_valid"`
	Reason      string `json:"reason,omitempty"`
}

// --- Handlers ---

func (s *Server) healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":          "ok",
		"node_id":         s.nodeID,
		"connected_peers": s.transport.ConnectedPeers(),
		"timestamp":       time.Now().UTC(),
	})
}

func (s *Server) keygen(c *gin.Context) {
	var req KeygenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if s.store.Exists(req.KeyID) {
		c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("key %q already exists", req.KeyID)})
		return
	}

	// For 3-party DKG, need both peers connected
	expectedPeers := req.Parties - 1
	if len(s.transport.ConnectedPeers()) < expectedPeers {
		if err := s.transport.WaitForPeers(expectedPeers, 30*time.Second); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": fmt.Sprintf("need %d peers connected, have %d", expectedPeers, len(s.transport.ConnectedPeers()))})
			return
		}
	}

	sessionID := fmt.Sprintf("dkg-%s-%d", req.KeyID, time.Now().UnixNano())
	result, err := s.dkg.Run(sessionID, req.KeyID, req.Threshold, req.Parties)
	if err != nil {
		log.Printf("[%s] DKG failed: %v", s.nodeID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("DKG failed: %v", err)})
		return
	}

	share := &keystore.ShareData{
		Share:     result.Share,
		PublicKey: result.PublicKey,
		ChainCode: result.ChainCode,
	}
	meta := &keystore.Metadata{
		KeyID:     req.KeyID,
		Path:      req.Path,
		Threshold: req.Threshold,
		Parties:   req.Parties,
		CreatedAt: time.Now().UTC(),
	}

	if err := s.store.Save(req.KeyID, share, meta); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("save key share: %v", err)})
		return
	}

	// Save full tss-lib save data for signing
	tssDataBytes, err := json.Marshal(result.SaveData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("marshal tss data: %v", err)})
		return
	}
	if err := s.store.SaveTSSData(req.KeyID, tssDataBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("save tss data: %v", err)})
		return
	}

	address, err := tron.AddressFromPublicKey(result.PublicKey)
	if err != nil {
		address = "derivation-error"
	}

	c.JSON(http.StatusOK, KeygenResponse{
		KeyID:     req.KeyID,
		PublicKey: hex.EncodeToString(result.PublicKey),
		ChainCode: hex.EncodeToString(result.ChainCode),
		Address:   address,
	})
}

func (s *Server) deriveChild(c *gin.Context) {
	var req DeriveChildRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	share, _, err := s.store.Load(req.MasterKeyID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("master key not found: %v", err)})
		return
	}

	// Idempotency: if this child was already derived, return the existing
	// data instead of redoing the tweak + overwriting the saved tss data.
	// Derivation is deterministic so the result is guaranteed to match.
	existingID := fmt.Sprintf("child_%s", pathToID(req.Path))
	if s.store.Exists(existingID) {
		existingShare, _, err := s.store.Load(existingID)
		if err == nil {
			address, aerr := tron.AddressFromPublicKey(existingShare.PublicKey)
			if aerr != nil {
				address = "derivation-error"
			}
			c.JSON(http.StatusOK, DeriveChildResponse{
				ChildKeyID: existingID,
				PublicKey:  hex.EncodeToString(existingShare.PublicKey),
				ChainCode:  hex.EncodeToString(existingShare.ChainCode),
				Address:    address,
				Path:       req.Path,
			})
			return
		}
	}

	result, err := derivation.DeriveChildShareFromPath(
		share.Share,
		share.PublicKey,
		share.ChainCode,
		req.Path,
	)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("derivation failed: %v", err)})
		return
	}

	childKeyID := fmt.Sprintf("child_%s", pathToID(req.Path))
	childShare := &keystore.ShareData{
		Share:     result.ChildShare,
		PublicKey: result.ChildPubKey,
		ChainCode: result.ChildChainCode,
	}
	childMeta := &keystore.Metadata{
		KeyID:     childKeyID,
		Path:      req.Path,
		Threshold: 2,
		Parties:   3,
		CreatedAt: time.Now().UTC(),
	}

	if err := s.store.Save(childKeyID, childShare, childMeta); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("save child share: %v", err)})
		return
	}

	// Also derive and persist tweaked tss-lib save data so the child key can be
	// used directly by /mpc/sign (same additive BIP32 tweak applied to Xi, BigXj
	// and ECDSAPub). Each node does this independently — no communication needed.
	masterSaveData, err := s.loadTSSData(req.MasterKeyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("load master tss data: %v", err)})
		return
	}
	tweakedSaveData, _, _, err := derivation.TweakTSSDataForPath(
		masterSaveData,
		share.PublicKey,
		share.ChainCode,
		req.Path,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("tweak tss data: %v", err)})
		return
	}
	tweakedBytes, err := json.Marshal(tweakedSaveData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("marshal tweaked tss data: %v", err)})
		return
	}
	if err := s.store.SaveTSSData(childKeyID, tweakedBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("save tweaked tss data: %v", err)})
		return
	}

	address, err := tron.AddressFromPublicKey(result.ChildPubKey)
	if err != nil {
		address = "derivation-error"
	}

	c.JSON(http.StatusOK, DeriveChildResponse{
		ChildKeyID: childKeyID,
		PublicKey:  hex.EncodeToString(result.ChildPubKey),
		ChainCode:  hex.EncodeToString(result.ChildChainCode),
		Address:    address,
		Path:       req.Path,
	})
}

func (s *Server) sign(c *gin.Context) {
	var req SignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	digest, err := hex.DecodeString(req.Digest)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "digest must be hex-encoded"})
		return
	}
	if len(digest) != 32 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "digest must be 32 bytes (SHA-256)"})
		return
	}

	_, _, err = s.store.Load(req.KeyID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("key not found: %v", err)})
		return
	}

	// Determine which 2 nodes will sign
	signers := req.Signers
	if len(signers) == 0 {
		// Auto-select: this node + first available peer
		signers, err = s.autoSelectSigners()
		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
			return
		}
	}

	// Validate signers
	if len(signers) != 2 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "exactly 2 signers required for 2-of-3 threshold"})
		return
	}
	if !contains(signers, s.nodeID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("this node (%s) must be one of the signers", s.nodeID)})
		return
	}

	// Check co-signer is connected
	coSigner := ""
	for _, id := range signers {
		if id != s.nodeID {
			coSigner = id
			break
		}
	}
	if !s.transport.IsPeerConnected(coSigner) {
		// Try fallback to another peer
		fallbackSigners, fbErr := s.autoSelectSigners()
		if fbErr != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": fmt.Sprintf("co-signer %s not connected and no fallback available", coSigner)})
			return
		}
		signers = fallbackSigners
		log.Printf("[%s] co-signer %s unavailable, falling back to %v", s.nodeID, coSigner, signers)
	}

	saveData, err := s.loadTSSData(req.KeyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("load tss data: %v", err)})
		return
	}

	sessionID := fmt.Sprintf("sign-%s-%d", req.KeyID, time.Now().UnixNano())
	sig, err := s.signer.Run(sessionID, req.KeyID, digest, saveData, signers)
	if err != nil {
		log.Printf("[%s] signing failed: %v", s.nodeID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("signing failed: %v", err)})
		return
	}

	c.JSON(http.StatusOK, SignResponse{
		R:       hex.EncodeToString(sig.R),
		S:       hex.EncodeToString(sig.S),
		V:       sig.V,
		Signers: signers,
	})
}

// autoSelectSigners picks this node + the first available connected peer.
// On client nodes the roster is learned from the hub, so we see real node IDs
// (e.g. s1, s3) instead of only "hub".
func (s *Server) autoSelectSigners() ([]string, error) {
	peers := s.transport.ConnectedPeers()
	if len(peers) == 0 {
		return nil, fmt.Errorf("no peers connected — need at least 1 peer for 2-of-3 signing")
	}
	return []string{s.nodeID, peers[0]}, nil
}

func (s *Server) validateAddress(c *gin.Context) {
	var req ValidateAddressRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	valid, reason := tron.ValidateAddress(req.Address)

	c.JSON(http.StatusOK, ValidateAddressResponse{
		Address:     req.Address,
		Valid:       valid,
		FormatValid: valid,
		Reason:      reason,
	})
}

func pathToID(path string) string {
	result := ""
	for _, c := range path {
		if c == '/' {
			result += "_"
		} else {
			result += string(c)
		}
	}
	return result
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
