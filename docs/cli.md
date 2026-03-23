# Cryptozoid CLI Reference

`cryptozoid` is a command-line tool for cryptographic operations, including
elliptic curve key generation, encryption, and decryption.

## Global Options

| Flag | Description |
|---|---|
| `-v`, `--verbose` | Enable verbose output |

---

## Commands

### `ec` — Elliptic Curve Operations

Provides key generation and ECDH-based encryption/decryption using elliptic
curve cryptography.

```
cryptozoid ec <subcommand> [options]
```

---

#### `ec generate` — Generate an ECDSA Key Pair

Generates an ECDSA private/public key pair and saves them as PEM files.

```
cryptozoid ec generate [options]
```

**Options:**

| Flag | Default | Description |
|---|---|---|
| `-c`, `--curve` | `P256` | Elliptic curve to use. Supported: `P256` |
| `-n`, `--name` | `ec` | Base name for the output key files |
| `-p`, `--path` | `.` | Directory where the key files will be saved |

**Output files:**

- `{path}/{name}_private.pem` — Private key (permissions: `0600`)
- `{path}/{name}_public.pem` — Public key

**Examples:**

```bash
# Generate with defaults (ec_private.pem and ec_public.pem in current dir)
cryptozoid ec generate

# Custom name and output directory
cryptozoid ec generate --name mykey --path /tmp/keys

# Short flags
cryptozoid ec generate -n mykey -p /tmp/keys
```

**Sample output:**

```
EC key pair generated.
Private key: /tmp/keys/mykey_private.pem
Private Key(bytes): 3b9f...
Public key: /tmp/keys/mykey_public.pem
Public Key(bytes): 04ab...
Curve: P-256
Private Key Size: 32
Public Key Size: 65
```

> **Note:** Currently only `P256` is enabled. `P384` and `P521` are defined
> but not yet supported.

---

#### `ec encrypt` — Encrypt a Value

Encrypts a plaintext string using ECDH key exchange and AES-GCM. The output
is a base64-encoded ciphertext.

```
cryptozoid ec encrypt [options] [TEXT]
```

**Options:**

| Flag | Default | Description |
|---|---|---|
| `-k`, `--key` | — | Direct path to the private key PEM file |
| `-n`, `--name` | — | Base name of the private key (resolves to `{name}_private.pem`) |
| `-p`, `--path` | `.` | Directory where the key file is located (used with `--name`) |

> You must provide either `--key` or `--name`. If both are provided, `--key`
> takes precedence.

**Input:**

The text to encrypt can be provided as a positional argument or piped via
stdin.

**Examples:**

```bash
# Using --key with a positional argument
cryptozoid ec encrypt --key ./ec_private.pem "hello world"

# Using --name and --path
cryptozoid ec encrypt --name mykey --path /tmp/keys "hello world"

# Using stdin pipe
echo "hello world" | cryptozoid ec encrypt --name mykey --path /tmp/keys

# Capture output to a file
cryptozoid ec encrypt --name mykey "secret message" > secret.b64
```

**Sample output:**

```
dGhpcyBpcyBhbiBleGFtcGxlIG91dHB1dA==
```

---

#### `ec decrypt` — Decrypt a Secret

Decrypts a base64-encoded ciphertext produced by `ec encrypt`.

```
cryptozoid ec decrypt [options] [SECRET]
```

**Options:**

| Flag | Default | Description |
|---|---|---|
| `-k`, `--key` | — | Direct path to the private key PEM file |
| `-n`, `--name` | — | Base name of the private key (resolves to `{name}_private.pem`) |
| `-p`, `--path` | `.` | Directory where the key file is located (used with `--name`) |

> You must provide either `--key` or `--name`. If both are provided, `--key`
> takes precedence.

**Input:**

The base64 secret can be provided as a positional argument or piped via stdin.

**Examples:**

```bash
# Using --key with a positional argument
cryptozoid ec decrypt --key ./ec_private.pem "dGhpcyBpcyBhbiBleGFtcGxlIG91dHB1dA=="

# Using --name and --path
cryptozoid ec decrypt --name mykey --path /tmp/keys "dGhpcyBpcyBhbiBleGFtcGxlIG91dHB1dA=="

# Piping from a file
cat secret.b64 | cryptozoid ec decrypt --name mykey --path /tmp/keys

# Full round-trip example
cryptozoid ec generate --name mykey
echo "my secret" | cryptozoid ec encrypt --name mykey | cryptozoid ec decrypt --name mykey
```

---

### `info` — Show Application Info

Displays basic application information.

```
cryptozoid info [options]
```

**Options:**

| Flag | Description |
|---|---|
| `-d`, `--detail` | Show detailed information |

**Examples:**

```bash
cryptozoid info
cryptozoid info --detail
```

---

## Key Resolution Logic

For `encrypt` and `decrypt`, the private key is resolved as follows:

1. If `--key` is provided → use it directly as the file path.
2. If `--name` is provided → resolve `{path}/{name}_private.pem`.
3. If neither is provided → error.

---

## Encryption Details

- **Key exchange:** ECDH (Elliptic Curve Diffie-Hellman)
- **Symmetric cipher:** AES-GCM
- **Output format:** Base64-encoded `ciphertext || nonce` (big-endian packed)
- **Key format:** PEM-encoded ECDSA private key
