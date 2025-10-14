# gensecpass2-simple

**Secure Password Generator - 100% Independent**

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://golang.org/doc/devel/release.html)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**NO NIST KEMs** • **NO Cloudflare** • **NO Corporate Dependencies**

---

## Why This Tool

Password storage doesn't need NIST KEMs (Kyber/McEliece). Those are for key exchange, not storage.

**What you actually need:**
- ✅ Strong KDF: **Argon2id** (quantum-resistant, memory-hard)
- ✅ Symmetric encryption: **AES-256-GCM**
- ✅ Physical entropy: **Keyboard + Mouse**

---

## Features

- 🔐 **Quantum-resistant**: Argon2id (128MB memory-hard)
- ⌨️🖱️ **Physical entropy**: Keyboard + Mouse timing
- 🛡️ **Memory protection**: MemGuard (mlock)
- 🔥 **Secure wipe**: DoD 5220.22-M (7-pass)
- 💾 **Simple format**: Argon2id + AES-256-GCM
- ✅ **Independent**: Zero corporate dependencies

---

## Quick Start

```bash
# Install
git clone https://github.com/yourusername/gensecpass2-simple
cd gensecpass2-simple
go mod download
go build -ldflags="-s -w" -o gensecpass2 gensecpass2-simple.go

# Generate password
./gensecpass2 -l 32

# Decrypt saved password
./gensecpass2 -decrypt -encfile password.txt.enc

# Secure wipe
./gensecpass2 -wipe -wipefile old_password.enc
```

---

## Usage Examples

```bash
# Standard password (16 chars)
./gensecpass2

# Custom length with verbose
./gensecpass2 -l 32 -v

# Save to custom file
./gensecpass2 -l 24 -o banking.enc

# Decrypt
./gensecpass2 -decrypt -encfile banking.enc

# Secure wipe (IRREVERSIBLE!)
./gensecpass2 -wipe -wipefile old.enc -v
```

---

## Security Stack

| Layer | Technology |
|-------|-----------|
| **Entropy** | Keyboard + Mouse timing (nanosecond precision) |
| **Random** | crypto/rand + memguard.NewBufferRandom() |
| **Memory** | MemGuard (mlock, secure wipe) |
| **KDF** | Argon2id (128MB, 4 iterations) |
| **Encryption** | AES-256-GCM (authenticated) |
| **Wipe** | DoD 5220.22-M (7-pass overwrite) |

---

## Why NO KEMs?

**KEMs (Kyber, McEliece) are for key exchange between two parties.**

For password storage:
- ✅ Argon2id is already quantum-resistant (memory-hard)
- ✅ Grover's algorithm only gives ~2x speedup
- ✅ No need for post-quantum key exchange

Using KEMs for storage is marketing hype.

---

## Best Practices

**Entropy Collection:**
- ⌨️ Random keys, varying timing, mix symbols
- 🖱️ Varied movements (circles, zigzags), change speed
- ❌ Don't use patterns or real words

**Passphrase:**
- Use 20+ characters
- Never reuse across services
- Consider Diceware method

**File Management:**
- Always use `-wipe` to delete (never `rm`)
- Backup encrypted files to external drive
- Different passwords for different services

---

## Comparison

| Feature | gensecpass2 | pwgen | KeePass | 1Password |
|---------|------------|-------|---------|-----------|
| Physical Entropy | ✅ ⌨️🖱️ | ❌ | ❌ | ❌ |
| Quantum-Resistant | ✅ | ❌ | ⚠️ | ⚠️ |
| DoD Secure Wipe | ✅ | ❌ | ❌ | ❌ |
| No Cloud | ✅ | ✅ | ✅ | ❌ |
| Independent | ✅ | ✅ | ✅ | ❌ |

---

## Performance

| Operation | Time |
|-----------|------|
| Argon2id KDF | ~350ms |
| Encryption | <1ms |
| Wipe 1MB | ~2s |
| Memory | ~150MB peak |

---

## Command-Line Options

```
-l int          Password length (8-256, default: 16)
-o string       Output file (default: password.txt.enc)
-decrypt        Decrypt saved password
-encfile string File to decrypt
-wipe           Secure wipe file (DoD 5220.22-M)
-wipefile string File to wipe
-v              Verbose output
-version        Show version
```

---

## License

MIT License

---

## Credits

- **Argon2**: Biryukov, Dinu, Khovratovich (2015)
- **MemGuard**: Awn Umar
- **DoD 5220.22-M**: U.S. Department of Defense

---

## Disclaimer

Software provided "as-is". Test thoroughly. Password security depends on passphrase strength and proper OpSec.

For security issues: Report privately to maintainers.
