# gensecpass

**Quantum-Safe Password Generator with Mouse Entropy Collection for Linux**

A secure password generator that combines multiple layers of cryptographic protection with physical entropy from mouse movements.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go)](https://golang.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-blue?logo=linux)](https://www.linux.org/)

---

## 🔐 Features

- **4-Layer Security Architecture**
  - Layer 1: Physical mouse entropy via X11 coordinate polling
  - Layer 2: MemGuard secure memory protection
  - Layer 3: Quantum-safe encryption layer (AES-256-GCM placeholder for McEliece)
  - Layer 4: Age encryption with scrypt key derivation

- **Mouse Entropy Collection**
  - Real-time X11 coordinate polling
  - 64 bytes of physical entropy collection
  - Optimized 80ms sampling rate
  - Visual progress bar with ETA and quality metrics
  - Timeout warnings for inactive periods

- **Secure Memory Management**
  - MemGuard locked memory pages
  - Protection against core dumps
  - Secure wipe with random overwrite
  - Automatic cleanup on exit

- **User-Friendly CLI**
  - Progress indicators with speed and ETA
  - Entropy quality ratings
  - Verbose mode for debugging
  - Interactive prompts

---

## 🏗️ Architecture

### Security Layers

```
┌─────────────────────────────────────────┐
│  Layer 4: Age Encryption (scrypt)       │
│  ┌───────────────────────────────────┐  │
│  │ Layer 3: Quantum-Safe Layer       │  │
│  │ ┌─────────────────────────────┐   │  │
│  │ │ Layer 2: MemGuard           │   │  │
│  │ │ ┌───────────────────────┐   │   │  │
│  │ │ │ Layer 1: Mouse        │   │   │  │
│  │ │ │ Entropy (X11)         │   │   │  │
│  │ │ │ + crypto/rand         │   │   │  │
│  │ │ └───────────────────────┘   │   │  │
│  │ └─────────────────────────────┘   │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

### Entropy Generation Process

1. **Mouse Entropy Collection** (64 bytes @ 80ms sampling)
   - X11 `XQueryPointer()` coordinate polling
   - XOR mixing: `mouseX ⊕ mouseY ⊕ timestamp ⊕ crypto/rand`
   - Visual feedback with progress bar

2. **Fused Entropy Creation**
   - Multi-round SHA-256 hashing
   - Combines crypto/rand + mouse entropy + nanosecond timestamps
   - Generates exactly required bytes for password length

3. **Password Generation**
   - Secure character selection from 94-character set
   - MemGuard locked buffer storage
   - Immutable after generation

4. **Optional Encryption**
   - Quantum-safe pre-encryption (AES-256-GCM placeholder)
   - Age encryption with user passphrase
   - Atomic file writes with SHA-256 verification

---

## 📋 Requirements

### System Requirements
- **OS**: Linux with X11 (Xorg)
- **Go**: 1.25 or higher
- **Libraries**:
  - `libX11` (X11 development files)
  - `libcrypto` (OpenSSL)

### Dependencies
```bash
# Debian/Ubuntu
sudo apt-get install libx11-dev

# Arch Linux
sudo pacman -S libx11

# Fedora/RHEL
sudo dnf install libX11-devel
```

---

## 🚀 Installation

### From Source

```bash
# Clone repository
git clone git@github.com:gabrix73/gensecpass.git
cd gensecpass

# Install Go dependencies
go mod download

# Build
go build \
  -ldflags="-s -w" \
  -trimpath \
  -buildmode=pie \
  -o gensecpass \
  gensecpass.go  

# Optional: Install to system
sudo cp gensecpass /usr/local/bin/
```

---

## 💻 Usage

### Basic Password Generation

```bash
# Generate 16-character password (default)
./gensecpass

# Generate 32-character password
./gensecpass -l 32

# Generate with verbose output
./gensecpass -l 24 -v
```

**Example Session:**
```
gensecpass v1.0.0 - Quantum-Safe Password Generator
🔒 4-Layer Security: Mouse + MemGuard + PostQuantum + Age
⚠️  Note: Using AES-256-GCM placeholder for quantum layer (McEliece coming soon)
Generating 16-character password...

🖱️  MANDATORY: Move your mouse to collect entropy...
Password length: 16 characters
Required mouse entropy: 64 bytes
Timeout: 2m0s | Warning after: 30s of inactivity

Progress: [=============================>] 98.4% (63/64 bytes) | 12 B/s | ETA: 0s
✅ Entropy collection completed!
📊 Collected: 64 bytes in 5.2s (avg: 12 B/s)
🔐 Entropy quality: Good (moderate activity)

Do you want to save the password to an encrypted file? (y/N): y
Enter passphrase for encryption:
Confirm passphrase:
🔒 4-layer encrypted file saved: password.txt.age
📊 File SHA-256 fingerprint: 5244f4ba9c2f0a50b7c6d58dfa636e23831b6bf5bf6b05f6bb231e49fa32673f

Password saved securely. Original password destroyed from memory.
```

### Decrypt Password

```bash
# Decrypt and display password
./gensecpass -decrypt -encfile password.txt.age

# With verbose output
./gensecpass -decrypt -encfile password.txt.age -v
```

**Example Decryption:**
```
Enter passphrase for decryption:
🔓 Decrypted Password: xK9$mP2@nQ7#vL4!

🔒 4-layer decryption completed successfully!
```

---

## ⚙️ Command-Line Options

```
Usage of ./gensecpass:
  -l int
        Password length (default: 16, min: 8, max: 128)

  -o string
        Output file path for encrypted password (default: "password.txt.age")
        Use '.' for current directory with default filename

  -decrypt
        Decrypt and display password from encrypted file

  -encfile string
        Encrypted file path to decrypt (use with -decrypt)

  -v
        Verbose output (shows detailed security layer information)

  -version
        Show version information
```

---

## 🔬 Security Details

### Mouse Entropy Specifications

- **Collection Method**: X11 `XQueryPointer()` coordinate polling
- **Sample Rate**: 80ms (optimized for speed/security balance)
- **Bytes Collected**: 64 bytes (fixed for all password lengths)
- **Mixing Algorithm**: `XOR(mouseX, mouseY, timestamp, crypto/rand)`
- **Timeout**: 120 seconds with warnings after 30s inactivity

### Entropy Quality Ratings

| Bytes/Second | Quality Rating |
|--------------|----------------|
| > 100 B/s    | Excellent      |
| > 50 B/s     | Very Good      |
| > 25 B/s     | Good           |
| > 10 B/s     | Fair           |
| < 10 B/s     | Poor           |

### Character Set

94 characters including:
- Lowercase: `a-z` (26 chars)
- Uppercase: `A-Z` (26 chars)
- Digits: `0-9` (10 chars)
- Symbols: `!@#$%^&*()-_=+[]{}|;:,.<>?/` (32 chars)

**Entropy per character**: ~6.55 bits
**16-char password**: ~105 bits of entropy

---

## 🛡️ Threat Model

### Protected Against

✅ **Memory Attacks**
- Core dumps (MemGuard protection)
- Swap exposure (locked pages)
- Memory scraping

✅ **Cryptographic Attacks**
- Weak RNG (crypto/rand + physical entropy)
- Dictionary attacks (high entropy + special chars)
- Brute force (configurable length up to 128 chars)

✅ **Future Quantum Attacks** (planned)
- Post-quantum layer placeholder (McEliece coming soon)

### Not Protected Against

❌ **Physical Attacks**
- Keyboard loggers
- Screen capture
- Shoulder surfing

❌ **System Compromise**
- Root-level malware
- Kernel-level attacks

### Best Practices

1. **Use on trusted systems only**
2. **Verify SHA-256 fingerprint** after encryption
3. **Use strong passphrases** for Age encryption
4. **Store encrypted files securely**
5. **Change password immediately** if you suspect compromise

---

## 📁 File Format

Encrypted password files use the **Age encryption format**:

```
age-encryption.org/v1
-> scrypt <salt> <work_factor>
<encrypted_key>
--- <MAC>
<ciphertext>
```

- **Algorithm**: Age with scrypt key derivation
- **Work Factor**: 18 (default scrypt parameter)
- **Inner Layer**: AES-256-GCM (quantum placeholder)

---

## 🗺️ Roadmap

### Current Version (1.0.0)
- ✅ X11 mouse entropy collection
- ✅ MemGuard secure memory
- ✅ Age encryption
- ✅ AES-256-GCM quantum placeholder

### Planned Features
- [ ] **Classic McEliece** integration (real post-quantum security)
- [ ] Wayland support (libinput)
- [ ] Windows support (via WSL or native)
- [ ] Hardware RNG support (`/dev/hwrng`)
- [ ] TOTP/HOTP integration
- [ ] Password strength estimator (zxcvbn)
- [ ] Clipboard integration with auto-clear
- [ ] Password manager integration (pass, KeePassXC)

---

## 🐛 Troubleshooting

### "Cannot open X11 display"

**Cause**: DISPLAY environment variable not set or X11 not running.

**Solution**:
```bash
# Check DISPLAY variable
echo $DISPLAY

# If empty, set it (usually :0 or :1)
export DISPLAY=:0

# Verify X11 is running
xdpyinfo | grep "name of display"
```

### "Permission denied" on mouse device

**Cause**: User not in `input` group (if using device raw access).

**Solution**: Not applicable for X11 version (no device access needed).

### Slow entropy collection

**Cause**: Insufficient mouse movement or slow movement patterns.

**Solution**: Move mouse in varied patterns (circles, zigzags, random movements).

### "Failed to decrypt"

**Cause**: Wrong passphrase or corrupted file.

**Solution**: Verify passphrase and check file SHA-256 fingerprint.

---

## 📜 License

MIT License - See [LICENSE](LICENSE) file for details.

---

## 🙏 Credits

### Libraries Used

- [filippo.io/age](https://github.com/FiloSottile/age) - Age encryption
- [github.com/awnumar/memguard](https://github.com/awnumar/memguard) - Secure memory
- [golang.org/x/term](https://pkg.go.dev/golang.org/x/term) - Terminal utilities
- [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) - Cryptographic primitives

### Inspiration

- [mouse_entropy](https://github.com/Ch1ffr3punk/mouse_entropy) - Original mouse entropy concept

---

## ⚠️ Disclaimer

This software is provided "as is" without warranty. The quantum-safe layer is currently a **placeholder** (AES-256-GCM with plaintext key) and does **NOT** provide post-quantum security yet. McEliece integration is planned for future releases.

**Use at your own risk.** Always follow security best practices and use strong passphrases.

---

## 📧 Contact

- **Author**: Gabx (gabrix73)
- **Email**: gabriel1@frozenstar.info
- **GitHub**: [@gabrix73](https://github.com/gabrix73)

---

**Made with ❤️ for the security community**
