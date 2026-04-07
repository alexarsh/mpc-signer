package transport

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Message is a protocol message exchanged between MPC nodes during DKG or signing.
type Message struct {
	Type      string          `json:"type"`       // "dkg", "sign", "dkg_init", "sign_init"
	SessionID string          `json:"session_id"` // links messages to a DKG or signing session
	From      string          `json:"from"`       // sender node ID
	To        string          `json:"to"`         // receiver node ID or "all" for broadcast
	Round     int             `json:"round"`      // protocol round number
	Payload   json.RawMessage `json:"payload"`    // tss-lib protocol message (opaque bytes)
}

// peerConn wraps a WebSocket connection with a write mutex.
type peerConn struct {
	id   string
	conn *websocket.Conn
	mu   sync.Mutex
}

func (p *peerConn) writeJSON(v interface{}) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.conn.WriteJSON(v)
}

// Transport manages WebSocket connections between MPC nodes.
// Hub mode (S1): accepts connections from multiple peers, routes messages between them.
// Client mode (S2, S3): single connection to the hub.
type Transport struct {
	nodeID string
	isHub  bool

	// Client mode: single connection to hub
	hubConn *peerConn

	// Hub mode: connections from peers
	peers   map[string]*peerConn
	peersMu sync.RWMutex

	// Client mode: roster of other node IDs the hub has advertised (hub +
	// other connected clients, excluding this node). Lets a client pick real
	// signer IDs instead of only knowing "hub".
	clientRoster   []string
	clientRosterMu sync.RWMutex

	// Message routing
	subscribers map[string]chan *Message // sessionID -> channel
	subMu       sync.RWMutex
	defaultCh   chan *Message // for messages without a matching subscriber (auto-join)
	done        chan struct{}
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true }, // PoC only
}

// NewHub creates a WebSocket hub transport (S1).
// The hub accepts connections from peers and routes messages between them.
func NewHub(nodeID string) *Transport {
	return &Transport{
		nodeID:      nodeID,
		isHub:       true,
		peers:       make(map[string]*peerConn),
		subscribers: make(map[string]chan *Message),
		defaultCh:   make(chan *Message, 100),
		done:        make(chan struct{}),
	}
}

// NewClient creates a WebSocket client transport that connects to the hub.
func NewClient(nodeID, serverURL string) (*Transport, error) {
	t := &Transport{
		nodeID:      nodeID,
		isHub:       false,
		subscribers: make(map[string]chan *Message),
		defaultCh:   make(chan *Message, 100),
		done:        make(chan struct{}),
	}

	conn, _, err := websocket.DefaultDialer.Dial(serverURL+"?id="+nodeID, nil)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", serverURL, err)
	}

	t.hubConn = &peerConn{id: "hub", conn: conn}
	go t.clientReadLoop()

	return t, nil
}

// HandleConnection is the HTTP handler for incoming WebSocket connections (hub side).
// Peers identify themselves via the ?id= query parameter.
func (t *Transport) HandleConnection(w http.ResponseWriter, r *http.Request) {
	peerID := r.URL.Query().Get("id")
	if peerID == "" {
		http.Error(w, "missing ?id= parameter", http.StatusBadRequest)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("websocket upgrade failed: %v", err)
		return
	}

	peer := &peerConn{id: peerID, conn: conn}

	t.peersMu.Lock()
	t.peers[peerID] = peer
	t.peersMu.Unlock()

	log.Printf("[%s] peer %s connected", t.nodeID, peerID)
	t.broadcastRoster()
	go t.hubReadLoop(peer)
}

// broadcastRoster sends the current list of node IDs (hub + all connected peers)
// to every connected client so they know the full set of reachable signers.
// Hub-only.
func (t *Transport) broadcastRoster() {
	if !t.isHub {
		return
	}
	t.peersMu.RLock()
	ids := make([]string, 0, len(t.peers)+1)
	ids = append(ids, t.nodeID) // hub itself
	for id := range t.peers {
		ids = append(ids, id)
	}
	t.peersMu.RUnlock()

	payload, err := json.Marshal(ids)
	if err != nil {
		log.Printf("[%s] marshal roster: %v", t.nodeID, err)
		return
	}

	t.peersMu.RLock()
	defer t.peersMu.RUnlock()
	for id, peer := range t.peers {
		msg := &Message{Type: "peers", From: t.nodeID, To: id, Payload: payload}
		if err := peer.writeJSON(msg); err != nil {
			log.Printf("[%s] send roster to %s: %v", t.nodeID, id, err)
		}
	}
}

// Subscribe returns a channel that receives messages for a specific session.
func (t *Transport) Subscribe(sessionID string) chan *Message {
	t.subMu.Lock()
	defer t.subMu.Unlock()
	ch := make(chan *Message, 100)
	t.subscribers[sessionID] = ch
	return ch
}

// Unsubscribe removes a session subscription.
func (t *Transport) Unsubscribe(sessionID string) {
	t.subMu.Lock()
	defer t.subMu.Unlock()
	delete(t.subscribers, sessionID)
}

// Send sends a message. Hub routes based on msg.To; client sends to hub.
func (t *Transport) Send(msg *Message) error {
	msg.From = t.nodeID

	if t.isHub {
		return t.hubSend(msg)
	}
	return t.clientSend(msg)
}

func (t *Transport) hubSend(msg *Message) error {
	t.peersMu.RLock()
	defer t.peersMu.RUnlock()

	for id, peer := range t.peers {
		if msg.To == "" || msg.To == "all" || msg.To == id {
			if err := peer.writeJSON(msg); err != nil {
				return fmt.Errorf("send to %s: %w", id, err)
			}
		}
	}
	return nil
}

func (t *Transport) clientSend(msg *Message) error {
	if t.hubConn == nil {
		return fmt.Errorf("not connected to hub")
	}
	return t.hubConn.writeJSON(msg)
}

// Receive returns the default channel for unrouted incoming messages.
func (t *Transport) Receive() <-chan *Message {
	return t.defaultCh
}

// ConnectedPeers returns the node IDs of other reachable nodes.
// On the hub this is the set of directly-connected clients.
// On a client this is the roster advertised by the hub (hub + other clients),
// so clients also see real signer IDs rather than just "hub".
func (t *Transport) ConnectedPeers() []string {
	if !t.isHub {
		t.clientRosterMu.RLock()
		defer t.clientRosterMu.RUnlock()
		ids := make([]string, len(t.clientRoster))
		copy(ids, t.clientRoster)
		return ids
	}

	t.peersMu.RLock()
	defer t.peersMu.RUnlock()
	ids := make([]string, 0, len(t.peers))
	for id := range t.peers {
		ids = append(ids, id)
	}
	return ids
}

// IsPeerConnected checks if a specific node is reachable.
// On hub: direct connection. On client: present in the advertised roster.
func (t *Transport) IsPeerConnected(peerID string) bool {
	if !t.isHub {
		t.clientRosterMu.RLock()
		defer t.clientRosterMu.RUnlock()
		for _, id := range t.clientRoster {
			if id == peerID {
				return true
			}
		}
		return false
	}
	t.peersMu.RLock()
	defer t.peersMu.RUnlock()
	_, ok := t.peers[peerID]
	return ok
}

// IsConnected returns true if the transport has at least one live link.
func (t *Transport) IsConnected() bool {
	if !t.isHub {
		return t.hubConn != nil
	}
	t.peersMu.RLock()
	defer t.peersMu.RUnlock()
	return len(t.peers) > 0
}

// WaitForPeers blocks until the specified number of peers are connected (hub only).
func (t *Transport) WaitForPeers(count int, timeout time.Duration) error {
	deadline := time.After(timeout)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-deadline:
			return fmt.Errorf("timeout waiting for %d peers (have %d)", count, len(t.ConnectedPeers()))
		case <-ticker.C:
			if len(t.ConnectedPeers()) >= count {
				return nil
			}
		}
	}
}

// WaitForPeer blocks until at least one peer connects (backward compat for clients).
func (t *Transport) WaitForPeer(timeout time.Duration) error {
	return t.WaitForPeers(1, timeout)
}

// Close shuts down the transport.
func (t *Transport) Close() error {
	close(t.done)
	if t.isHub {
		t.peersMu.Lock()
		defer t.peersMu.Unlock()
		for _, peer := range t.peers {
			peer.conn.Close()
		}
		return nil
	}
	if t.hubConn != nil {
		return t.hubConn.conn.Close()
	}
	return nil
}

// hubReadLoop reads messages from a connected peer and routes them.
func (t *Transport) hubReadLoop(peer *peerConn) {
	defer func() {
		t.peersMu.Lock()
		delete(t.peers, peer.id)
		t.peersMu.Unlock()
		peer.conn.Close()
		log.Printf("[%s] peer %s disconnected", t.nodeID, peer.id)
		t.broadcastRoster()
	}()

	for {
		select {
		case <-t.done:
			return
		default:
		}

		var msg Message
		if err := peer.conn.ReadJSON(&msg); err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("[%s] read error from %s: %v", t.nodeID, peer.id, err)
			}
			return
		}

		// Forward to other peers if needed
		if msg.To == "all" || (msg.To != "" && msg.To != t.nodeID) {
			t.forwardMessage(&msg, peer.id)
		}

		// Route locally if message is for us
		if msg.To == "" || msg.To == "all" || msg.To == t.nodeID {
			t.routeLocal(&msg)
		}
	}
}

// forwardMessage sends a message to other peers (hub only).
func (t *Transport) forwardMessage(msg *Message, fromPeerID string) {
	t.peersMu.RLock()
	defer t.peersMu.RUnlock()

	for id, peer := range t.peers {
		if id == fromPeerID {
			continue // don't echo back to sender
		}
		if msg.To == "all" || msg.To == id {
			if err := peer.writeJSON(msg); err != nil {
				log.Printf("[%s] forward to %s failed: %v", t.nodeID, id, err)
			}
		}
	}
}

// routeLocal routes a message to the appropriate local subscriber or default channel.
func (t *Transport) routeLocal(msg *Message) {
	t.subMu.RLock()
	ch, ok := t.subscribers[msg.SessionID]
	t.subMu.RUnlock()

	if ok {
		ch <- msg
	} else {
		t.defaultCh <- msg
	}
}

// clientReadLoop reads messages from the hub (client mode).
func (t *Transport) clientReadLoop() {
	for {
		select {
		case <-t.done:
			return
		default:
		}

		var msg Message
		if err := t.hubConn.conn.ReadJSON(&msg); err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("[%s] read error: %v", t.nodeID, err)
			}
			return
		}

		// Intercept roster updates from the hub — don't route to subscribers.
		if msg.Type == "peers" {
			var ids []string
			if err := json.Unmarshal(msg.Payload, &ids); err != nil {
				log.Printf("[%s] parse roster: %v", t.nodeID, err)
				continue
			}
			filtered := make([]string, 0, len(ids))
			for _, id := range ids {
				if id != t.nodeID {
					filtered = append(filtered, id)
				}
			}
			t.clientRosterMu.Lock()
			t.clientRoster = filtered
			t.clientRosterMu.Unlock()
			log.Printf("[%s] peer roster updated: %v", t.nodeID, filtered)
			continue
		}

		t.routeLocal(&msg)
	}
}
