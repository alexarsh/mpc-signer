# MPC Signer

## What is this?

A crypto wallet where **no single server ever holds the full private key**.

Instead of one server having the private key (which is a single point of failure — if hacked, all funds are gone), we **split the key into three pieces** and give each piece to a separate server. Any **2 of 3** servers can sign a transaction — but no single server can sign alone.

```
  ┌──────────┐     ┌──────────┐     ┌──────────┐
  │ S1 Node  │     │ S2 Node  │     │ S3 Node  │
  │ (Hub)    │     │          │     │          │
  │ holds    │     │ holds    │     │ holds    │
  │ piece 1  │◄───►│ piece 2  │     │ piece 3  │
  │ of key   │ WS  │ of key   │     │ of key   │
  └──────────┘     └──────────┘     └──────────┘
       ▲                                 ▲
       └──────────── WebSocket ──────────┘
       ▲
       │ HTTPS
  ┌────┴────────────────────────────────────┐
  │          Application Server             │
  │   (calls S1 to coordinate signing)      │
  └─────────────────────────────────────────┘
```

S1 acts as the **hub** — S2 and S3 connect to S1 via WebSocket. S2 and S3 do not communicate directly.

- **To create a wallet:** All 3 servers cooperate to generate key pieces (DKG). No server ever sees the full key.
- **To create a sub-address:** Each server independently derives a child key from its piece. No communication needed.
- **To sign a transaction:** Any 2 of 3 servers cooperate over WebSocket. If one server is down, the other two can still sign.

This is called **MPC (Multi-Party Computation)** with **2-of-3 threshold signing**.

## Features

1. Three servers generate a shared key without any server knowing the full key (DKG)
2. Each server independently derives child keys for new wallet addresses (BIP32)
3. All three servers derive the **same address** from the same path
4. Any 2 of 3 servers can sign a transaction — fault tolerance if one server is down
5. Address validation for TRON format

## Project Structure

```
mpc-signer/
├── cmd/
│   ├── s1/main.go                  # Server 1 entry point (WebSocket hub)
│   ├── s2/main.go                  # Server 2 entry point (WebSocket client)
│   └── s3/main.go                  # Server 3 entry point (WebSocket client)
├── internal/
│   ├── api/handlers.go             # REST API endpoints
│   ├── dkg/dkg.go                  # Distributed Key Generation (GG20)
│   ├── signer/signer.go           # 2-of-3 threshold signing (GG20)
│   ├── derivation/bip32.go        # BIP32 child key derivation on shares
│   ├── keystore/keystore.go       # AES-256-GCM encrypted key share storage
│   ├── transport/websocket.go     # WebSocket hub + client communication
│   └── tron/address.go            # TRON address derivation + validation
├── config/
│   ├── config.go                   # YAML config loader
│   ├── s1.yaml                     # S1 config (port 18551, hub)
│   ├── s2.yaml                     # S2 config (port 18552, client)
│   └── s3.yaml                     # S3 config (port 18553, client)
├── go.mod
├── go.sum
├── .gitignore
└── README.md
```

## API Endpoints

| Method | Endpoint | What it does |
|--------|----------|-------------|
| `GET`  | `/health` | Check if the node is running and which peers are connected |
| `POST` | `/mpc/keygen` | Generate a new master key (DKG — all 3 nodes cooperate) |
| `POST` | `/mpc/derive-child` | Derive a child key for a wallet address (local math, no communication) |
| `POST` | `/mpc/sign` | Sign a transaction digest (any 2 of 3 nodes cooperate) |
| `POST` | `/wallet/validate-address` | Check if a TRON address format is valid |

## How to Run

### Prerequisites

- **Go 1.21+** (check with `go version`)
- Everything runs locally — no cloud access needed

### Step 1: Install dependencies

```bash
cd mpc-signer
go mod tidy
```

This downloads all Go dependencies. Takes ~30 seconds on first run.

### Step 2: Start S1 (Terminal 1)

```bash
go run ./cmd/s1 --config config/s1.yaml
```

You should see:
```
Starting MPC Node s1 (WebSocket hub)
[s1] WebSocket hub listening on 0.0.0.0:19552
[s1] REST API listening on 0.0.0.0:18551
```

### Step 3: Start S2 (Terminal 2)

Open a **new terminal**, `cd` to the same directory, and run:

```bash
go run ./cmd/s2 --config config/s2.yaml
```

You should see:
```
Starting MPC Node s2 (WebSocket client)
[s2] connected to S1 at ws://localhost:19552/ws
[s2] REST API listening on 0.0.0.0:18552
```

### Step 4: Start S3 (Terminal 3)

Open **another terminal**:

```bash
go run ./cmd/s3 --config config/s3.yaml
```

You should see:
```
Starting MPC Node s3 (WebSocket client)
[s3] connected to S1 at ws://localhost:19552/ws
[s3] REST API listening on 0.0.0.0:18553
```

### Step 5: Verify all nodes are running (Terminal 4)

Open a **fourth terminal** for running curl commands:

```bash
curl -s http://localhost:18551/health | python3 -m json.tool
```

Should show `"connected_peers": ["s2", "s3"]`.

```bash
curl -s http://localhost:18552/health | python3 -m json.tool
curl -s http://localhost:18553/health | python3 -m json.tool
```

Both should show `"connected_peers": ["hub"]`.

### Step 6: Generate a master key (DKG)

This is the core MPC operation. S1 coordinates with S2 and S3 over WebSocket to jointly generate a key pair. Takes ~1-2 minutes (safe prime generation on 3 nodes).

```bash
curl -s -X POST http://localhost:18551/mpc/keygen \
  -H "Content-Type: application/json" \
  -d '{
    "key_id": "master",
    "path": "m/44h/195h/0h",
    "threshold": 2,
    "parties": 3
  }' | python3 -m json.tool
```

Expected output:
```json
{
    "key_id": "master",
    "public_key": "04...(hex)...",
    "chain_code": "...(hex)...",
    "address": "T..."
}
```

You should see in the S2 and S3 terminals:
```
[s2] received dkg_init: session=... threshold=2 parties=3
[s2] DKG complete! key=master address=T...
```
```
[s3] received dkg_init: session=... threshold=2 parties=3
[s3] DKG complete! key=master address=T...
```

All 3 nodes should show the **same address**.

### Step 7: Derive child addresses

Call derive-child on **all 3 nodes independently** with the same path:

```bash
# On S1
curl -s -X POST http://localhost:18551/mpc/derive-child \
  -H "Content-Type: application/json" \
  -d '{"master_key_id": "master", "path": "0/0"}' | python3 -m json.tool

# On S2
curl -s -X POST http://localhost:18552/mpc/derive-child \
  -H "Content-Type: application/json" \
  -d '{"master_key_id": "master", "path": "0/0"}' | python3 -m json.tool

# On S3
curl -s -X POST http://localhost:18553/mpc/derive-child \
  -H "Content-Type: application/json" \
  -d '{"master_key_id": "master", "path": "0/0"}' | python3 -m json.tool
```

All 3 should return the **same `public_key` and `address`**. This proves each node independently derives child keys from its share without communicating.

### Step 8: Sign a transaction

To sign, provide the `key_id`, a hex-encoded 32-byte SHA-256 digest, and optionally which 2 nodes should sign:

```bash
# Sign with S1 + first available peer (auto-select)
curl -s -X POST http://localhost:18551/mpc/sign \
  -H "Content-Type: application/json" \
  -d '{
    "key_id": "master",
    "digest": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
  }' | python3 -m json.tool
```

You can explicitly choose which 2 nodes sign:

```bash
# Sign with S1 + S3
curl -s -X POST http://localhost:18551/mpc/sign \
  -H "Content-Type: application/json" \
  -d '{
    "key_id": "master",
    "digest": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    "signers": ["s1", "s3"]
  }' | python3 -m json.tool
```

The response includes which nodes signed:
```json
{
    "r": "...",
    "s": "...",
    "v": 0,
    "signers": ["s1", "s3"]
}
```

If the requested co-signer is unavailable, the system automatically falls back to another connected peer.

### Step 9: Validate an address

```bash
# Valid TRON address
curl -s -X POST http://localhost:18551/wallet/validate-address \
  -H "Content-Type: application/json" \
  -d '{"address": "TJRabPrwbZy45sbavfcjinPJC18kjpRTv8"}' | python3 -m json.tool

# Invalid (Ethereum address)
curl -s -X POST http://localhost:18551/wallet/validate-address \
  -H "Content-Type: application/json" \
  -d '{"address": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD"}' | python3 -m json.tool
```

### Step 10: Test error handling

```bash
# Duplicate keygen (should return 409)
curl -s -X POST http://localhost:18551/mpc/keygen \
  -H "Content-Type: application/json" \
  -d '{"key_id": "master", "path": "m/44h/195h/0h", "threshold": 2, "parties": 3}' | python3 -m json.tool

# Hardened path after DKG (should return 400)
curl -s -X POST http://localhost:18551/mpc/derive-child \
  -H "Content-Type: application/json" \
  -d '{"master_key_id": "master", "path": "44h/0"}' | python3 -m json.tool

# Non-existent key (should return 404)
curl -s -X POST http://localhost:18551/mpc/derive-child \
  -H "Content-Type: application/json" \
  -d '{"master_key_id": "nonexistent", "path": "0/0"}' | python3 -m json.tool

# Invalid digest length for signing (should return 400)
curl -s -X POST http://localhost:18551/mpc/sign \
  -H "Content-Type: application/json" \
  -d '{"key_id": "master", "digest": "abcd"}' | python3 -m json.tool

# Wrong number of signers (should return 400)
curl -s -X POST http://localhost:18551/mpc/sign \
  -H "Content-Type: application/json" \
  -d '{"key_id": "master", "digest": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", "signers": ["s1"]}' | python3 -m json.tool
```

## Default Ports

| Component | Port |
|-----------|------|
| S1 REST API | 18551 |
| S2 REST API | 18552 |
| S3 REST API | 18553 |
| WebSocket (S1 hub, S2+S3 connect) | 19552 |

Ports are configurable in `config/s1.yaml`, `config/s2.yaml`, and `config/s3.yaml`.

## Key Concepts (Simple Explanation)

### DKG (Distributed Key Generation)
Three servers generate a key together. Each gets a "piece" (share). No server ever sees the complete key. Like three people each writing part of a password — none knows the full password.

### BIP32 Child Derivation
From one master key, you can mathematically derive unlimited child keys (sub-wallets). Each server does this independently using its own share — no need to talk to each other. All three get the same result because the math is deterministic.

### 2-of-3 Threshold Signing (GG20)
To sign a transaction, any 2 of the 3 servers exchange multiple rounds of messages over WebSocket. At the end, a valid signature is produced — but neither server ever reconstructed the full key during the process. If one server is down, the other two can still sign.

### TRON Address
A TRON address is derived from a public key using Keccak-256 hashing and Base58Check encoding. Starts with `T`, 34 characters long.

## Tech Stack

- **Go 1.21+** — S1, S2, and S3 MPC nodes
- **tss-lib v1.5.0** (by BNB Chain) — DKG and signing protocol (GG20)
- **btcec/v2** — secp256k1 elliptic curve operations
- **gin** — REST API framework
- **gorilla/websocket** — Node-to-node communication (hub topology)
- **AES-256-GCM + Argon2id** — Key share encryption at rest
- **TRON** — Address derivation and validation
