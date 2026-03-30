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
	To        string          `json:"to"`         // receiver node ID
	Round     int             `json:"round"`      // protocol round number
	Payload   json.RawMessage `json:"payload"`    // tss-lib protocol message (opaque bytes)
}

// Transport manages the WebSocket connection between two MPC nodes.
type Transport struct {
	nodeID      string
	conn        *websocket.Conn
	mu          sync.Mutex
	subscribers map[string]chan *Message // sessionID -> channel
	subMu       sync.RWMutex
	defaultCh   chan *Message // for messages without a matching subscriber (auto-join)
	done        chan struct{}
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true }, // PoC only
}

// NewServer creates a WebSocket server transport.
func NewServer(nodeID string) *Transport {
	return &Transport{
		nodeID:      nodeID,
		subscribers: make(map[string]chan *Message),
		defaultCh:   make(chan *Message, 100),
		done:        make(chan struct{}),
	}
}

// NewClient creates a WebSocket client transport that connects to a server.
func NewClient(nodeID, serverURL string) (*Transport, error) {
	t := &Transport{
		nodeID:      nodeID,
		subscribers: make(map[string]chan *Message),
		defaultCh:   make(chan *Message, 100),
		done:        make(chan struct{}),
	}

	conn, _, err := websocket.DefaultDialer.Dial(serverURL, nil)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", serverURL, err)
	}

	t.conn = conn
	go t.readLoop()

	return t, nil
}

// HandleConnection is the HTTP handler for incoming WebSocket connections (server side).
func (t *Transport) HandleConnection(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("websocket upgrade failed: %v", err)
		return
	}

	t.mu.Lock()
	t.conn = conn
	t.mu.Unlock()

	log.Printf("[%s] peer connected", t.nodeID)
	go t.readLoop()
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

// Send sends a message to the peer.
func (t *Transport) Send(msg *Message) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn == nil {
		return fmt.Errorf("not connected")
	}

	msg.From = t.nodeID
	return t.conn.WriteJSON(msg)
}

// Receive returns the default channel for unrouted incoming messages.
func (t *Transport) Receive() <-chan *Message {
	return t.defaultCh
}

// WaitForPeer blocks until a peer connects.
func (t *Transport) WaitForPeer(timeout time.Duration) error {
	deadline := time.After(timeout)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-deadline:
			return fmt.Errorf("timeout waiting for peer connection")
		case <-ticker.C:
			t.mu.Lock()
			connected := t.conn != nil
			t.mu.Unlock()
			if connected {
				return nil
			}
		}
	}
}

// IsConnected returns true if a peer is connected.
func (t *Transport) IsConnected() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.conn != nil
}

// Close shuts down the transport.
func (t *Transport) Close() error {
	close(t.done)
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn != nil {
		return t.conn.Close()
	}
	return nil
}

func (t *Transport) readLoop() {
	for {
		select {
		case <-t.done:
			return
		default:
		}

		t.mu.Lock()
		conn := t.conn
		t.mu.Unlock()

		if conn == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		var msg Message
		if err := conn.ReadJSON(&msg); err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("[%s] read error: %v", t.nodeID, err)
			}
			return
		}

		// Route to session subscriber if one exists
		t.subMu.RLock()
		ch, ok := t.subscribers[msg.SessionID]
		t.subMu.RUnlock()

		if ok {
			ch <- &msg
		} else {
			// No subscriber — goes to default channel (triggers auto-join on peer)
			t.defaultCh <- &msg
		}
	}
}
