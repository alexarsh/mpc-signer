# MPC Signer

## What is this?

A crypto wallet where **no single server ever holds the full private key**.

Instead of one server having the private key (which is a single point of failure — if hacked, all funds are gone), we **split the key into two pieces** and give each piece to a separate server:

```
  ┌──────────┐          ┌──────────┐
  │ S1 Node  │          │ S2 Node  │
  │          │          │          │
  │ holds    │          │ holds    │
  │ piece 1  │◄────────►│ piece 2  │
  │ of key   │ WebSocket│ of key   │
  └──────────┘          └──────────┘
       ▲                      ▲
       │ HTTPS                │ HTTPS
       │                      │
  ┌────┴──────────────────────┴────┐
  │        Application Server      │
  │   (orchestrates everything)    │
  └────────────────────────────────┘
```

- **To create a wallet:** Both servers cooperate to generate key pieces (DKG). Neither ever sees the full key.
- **To create a sub-address:** Each server independently derives a child key from its piece. No communication needed.
- **To sign a transaction:** Both servers cooperate over WebSocket. Neither can sign alone.

This is called **MPC (Multi-Party Computation)** with **threshold signing**.

## Features

1. Two servers generate a shared key without either knowing the full key (DKG)
2. Each server independently derives child keys for new wallet addresses (BIP32)
3. Both servers derive the **same address** from the same path
4. Address validation for TRON format

## Project Structure

```
mpc-signer/
├── cmd/
│   ├── s1/main.go                  # Server 1 entry point (WebSocket server)
│   └── s2/main.go                  # Server 2 entry point (WebSocket client)
├── internal/
│   ├── api/handlers.go             # REST API endpoints
│   ├── dkg/dkg.go                  # Distributed Key Generation (GG20)
│   ├── signer/signer.go           # Threshold signing (GG20)
│   ├── derivation/bip32.go        # BIP32 child key derivation on shares
│   ├── keystore/keystore.go       # AES-256-GCM encrypted key share storage
│   ├── transport/websocket.go     # WebSocket communication between nodes
│   └── tron/address.go            # TRON address derivation + validation
├── config/
│   ├── config.go                   # YAML config loader
│   ├── s1.yaml                     # S1 config (port 18551)
│   └── s2.yaml                     # S2 config (port 18552)
├── go.mod
├── go.sum
├── .gitignore
└── README.md
```

## API Endpoints

| Method | Endpoint | What it does |
|--------|----------|-------------|
| `GET`  | `/health` | Check if the node is running and peer is connected |
| `POST` | `/mpc/keygen` | Generate a new master key (DKG — both nodes cooperate) |
| `POST` | `/mpc/derive-child` | Derive a child key for a wallet address (local math, no communication) |
| `POST` | `/mpc/sign` | Sign a transaction digest (both nodes cooperate) |
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
Starting MPC Node s1 (WebSocket server)
[s1] WebSocket server listening on 0.0.0.0:19552
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

### Step 4: Verify both nodes are running (Terminal 3)

Open a **third terminal** for running curl commands:

```bash
curl -s http://localhost:18551/health | python3 -m json.tool
curl -s http://localhost:18552/health | python3 -m json.tool
```

Both should show `"status": "ok"` and `"peer": true`.

### Step 5: Generate a master key (DKG)

This is the core MPC operation. S1 coordinates with S2 over WebSocket to jointly generate a key pair. Takes ~10-15 seconds.

```bash
curl -s -X POST http://localhost:18551/mpc/keygen \
  -H "Content-Type: application/json" \
  -d '{
    "key_id": "master",
    "path": "m/44h/195h/0h",
    "threshold": 2,
    "parties": 2
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

You should also see in the S2 terminal:
```
[s2] received dkg_init: session=... threshold=2 parties=2
[s2] DKG complete! key=master address=T...
```

Both nodes should show the **same address**.

### Step 6: Derive child addresses

Call derive-child on **both nodes independently** with the same path:

```bash
# On S1
curl -s -X POST http://localhost:18551/mpc/derive-child \
  -H "Content-Type: application/json" \
  -d '{"master_key_id": "master", "path": "0/0"}' | python3 -m json.tool

# On S2
curl -s -X POST http://localhost:18552/mpc/derive-child \
  -H "Content-Type: application/json" \
  -d '{"master_key_id": "master", "path": "0/0"}' | python3 -m json.tool
```

Both should return the **same `public_key` and `address`**. This proves that each node can independently derive child keys from its share without communicating.

Try more paths:
```bash
# Sub-wallet 1
curl -s -X POST http://localhost:18551/mpc/derive-child \
  -H "Content-Type: application/json" \
  -d '{"master_key_id": "master", "path": "0/1"}' | python3 -m json.tool

# Sub-wallet 2
curl -s -X POST http://localhost:18551/mpc/derive-child \
  -H "Content-Type: application/json" \
  -d '{"master_key_id": "master", "path": "0/2"}' | python3 -m json.tool
```

Each path produces a different address.

### Step 7: Sign a transaction

To sign, provide the `key_id` and a hex-encoded 32-byte SHA-256 digest of the transaction:

```bash
curl -s -X POST http://localhost:18551/mpc/sign \
  -H "Content-Type: application/json" \
  -d '{
    "key_id": "master",
    "digest": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
  }' | python3 -m json.tool
```

Both nodes cooperate over WebSocket to produce the signature — neither ever reconstructs the full private key.

### Step 8: Validate an address

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

### Step 9: Test error handling

```bash
# Duplicate keygen (should return 409)
curl -s -X POST http://localhost:18551/mpc/keygen \
  -H "Content-Type: application/json" \
  -d '{"key_id": "master", "path": "m/44h/195h/0h", "threshold": 2, "parties": 2}' | python3 -m json.tool

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
```

## Default Ports

| Component | Port |
|-----------|------|
| S1 REST API | 18551 |
| S2 REST API | 18552 |
| WebSocket (S1 listens, S2 connects) | 19552 |

Ports are configurable in `config/s1.yaml` and `config/s2.yaml`.

## Key Concepts (Simple Explanation)

### DKG (Distributed Key Generation)
Two servers generate a key together. Each gets a "piece" (share). Neither ever sees the complete key. Like two people each writing half a password — neither knows the full password.

### BIP32 Child Derivation
From one master key, you can mathematically derive unlimited child keys (sub-wallets). Each server does this independently using its own share — no need to talk to each other. Both get the same result because the math is deterministic.

### Threshold Signing (GG20)
To sign a transaction, both servers exchange multiple rounds of messages over WebSocket. At the end, a valid signature is produced — but neither server ever reconstructed the full key during the process.

### TRON Address
A TRON address is derived from a public key using Keccak-256 hashing and Base58Check encoding. Starts with `T`, 34 characters long.

## Tech Stack

- **Go 1.21+** — S1 and S2 MPC nodes
- **tss-lib v1.5.0** (by BNB Chain) — DKG and signing protocol (GG20)
- **btcec/v2** — secp256k1 elliptic curve operations
- **gin** — REST API framework
- **gorilla/websocket** — Node-to-node communication
- **AES-256-GCM + Argon2id** — Key share encryption at rest
- **TRON** — Address derivation and validation
