# Cryptozoid

Cryptography and security solutions by idzoid, empowering secure communications
for idzoid and its clients.

## Features

- **Elliptic Curve Key Generation** — Generate ECDSA key pairs (P-256) as PEM files
- **ECDH Encryption** — Encrypt data using Elliptic Curve Diffie-Hellman + AES-GCM
- **ECDH Decryption** — Decrypt secrets using the same private key
- **Flexible key resolution** — Reference keys by file path or by name convention

## Installation

```bash
go install github.com/idzoid/cryptozoid/cmd/cryptozoid@latest
```

Or build from source:

```bash
git clone https://github.com/idzoid/cryptozoid.git
cd cryptozoid
go build -o cryptozoid ./cmd/cryptozoid
```

## Quick Start

```bash
# 1. Generate a key pair
cryptozoid ec generate --name mykey --path ./keys

# 2. Encrypt a message
echo "my secret" | cryptozoid ec encrypt --name mykey --path ./keys

# 3. Decrypt it back
echo "<base64-output>" | cryptozoid ec decrypt --name mykey --path ./keys

# Round-trip in one line
cryptozoid ec generate --name mykey
echo "my secret" | cryptozoid ec encrypt --name mykey | cryptozoid ec decrypt --name mykey
```

## Documentation

- [CLI Reference](docs/cli.md) — Full command reference for the `cryptozoid` CLI
- [Go Package Reference](https://pkg.go.dev/github.com/idzoid/cryptozoid) — API docs for using cryptozoid as a library

## License

This project is licensed under the [MIT License](LICENSE).
