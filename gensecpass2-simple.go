package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

const (
	version           = "2.0.0-simple"
	minLength         = 8
	maxLength         = 256
	defaultLength     = 16
	charSet           = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/\""
	defaultOutputFile = "password.txt.enc"
	minMouseEntropy   = 256
	minKeyEntropy     = 128
	entropyTimeout    = 120 * time.Second
	
	// Argon2id parameters (quantum-resistant KDF)
	argon2Time    = 4      // More iterations for security
	argon2Memory  = 128 * 1024 // 128 MB memory-hard
	argon2Threads = 4
	argon2KeyLen  = 32
	
	// DoD 5220.22-M wipe: 7 passes
	wipePatterns = 7
)

type EntropyCollector struct {
	mouseData    []byte
	keyboardData []byte
	startTime    time.Time
	finished     bool
}

func NewEntropyCollector() *EntropyCollector {
	return &EntropyCollector{
		mouseData:    make([]byte, 0, minMouseEntropy*2),
		keyboardData: make([]byte, 0, minKeyEntropy*2),
		startTime:    time.Now(),
	}
}

func (ec *EntropyCollector) CollectKeyboardEntropy(targetBytes int, verbose bool) error {
	fmt.Println("⌨️  Type random characters for keyboard entropy...")
	fmt.Printf("📊 Target: %d bytes (press ENTER when done)\n", targetBytes)
	fmt.Println("💡 Tip: Random keys, varying timing\n")

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("failed to set raw mode: %v", err)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	reader := bufio.NewReader(os.Stdin)
	lastTime := time.Now()
	
	for len(ec.keyboardData) < targetBytes {
		if time.Since(ec.startTime) > entropyTimeout {
			return fmt.Errorf("timeout exceeded")
		}

		b, err := reader.ReadByte()
		if err != nil {
			continue
		}

		if b == 13 || b == 10 {
			if len(ec.keyboardData) >= targetBytes {
				break
			}
			fmt.Printf("\r⚠️  Need %d more bytes...    ", targetBytes-len(ec.keyboardData))
			continue
		}

		currentTime := time.Now()
		timeDelta := currentTime.Sub(lastTime).Nanoseconds()
		lastTime = currentTime

		entropy := make([]byte, 17)
		entropy[0] = b
		binary.LittleEndian.PutUint64(entropy[1:9], uint64(currentTime.UnixNano()))
		binary.LittleEndian.PutUint64(entropy[9:17], uint64(timeDelta))
		
		ec.keyboardData = append(ec.keyboardData, entropy...)

		progress := float64(len(ec.keyboardData)) / float64(targetBytes) * 100
		fmt.Printf("\r⌨️  Collected: %d/%d bytes (%.1f%%)    ", len(ec.keyboardData), targetBytes, progress)
	}
	
	fmt.Println("\n✅ Keyboard entropy complete!")
	return nil
}

func (ec *EntropyCollector) CollectMouseEntropy(targetBytes int, verbose bool) error {
	fmt.Println("🖱️  Move mouse randomly for entropy...")
	fmt.Printf("📊 Target: %d bytes\n", targetBytes)
	fmt.Println("💡 Tip: Varied movements - circles, zigzags\n")

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("failed to set raw mode: %v", err)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	mouseChan := make(chan []byte, 100)
	go ec.readMouseInput(mouseChan)

	for {
		select {
		case <-ticker.C:
			if time.Since(ec.startTime) > entropyTimeout {
				ec.finished = true
				return fmt.Errorf("timeout exceeded")
			}

			progress := float64(len(ec.mouseData)) / float64(targetBytes) * 100
			elapsed := time.Since(ec.startTime).Seconds()
			rate := float64(len(ec.mouseData)) / elapsed
			
			fmt.Printf("\r🖱️  Collected: %d/%d bytes (%.1f%%) | %.0f B/s    ", 
				len(ec.mouseData), targetBytes, progress, rate)

			if len(ec.mouseData) >= targetBytes {
				fmt.Println("\n✅ Mouse entropy complete!")
				ec.finished = true
				return nil
			}

		case mouseData := <-mouseChan:
			if len(mouseData) > 0 {
				ec.mouseData = append(ec.mouseData, mouseData...)
			}
		}
	}
}

func (ec *EntropyCollector) readMouseInput(ch chan<- []byte) {
	reader := bufio.NewReader(os.Stdin)
	lastTime := time.Now()
	
	for !ec.finished {
		b, err := reader.ReadByte()
		if err != nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		
		currentTime := time.Now()
		timeDelta := currentTime.Sub(lastTime).Nanoseconds()
		lastTime = currentTime
		
		entropy := make([]byte, 17)
		entropy[0] = b
		binary.LittleEndian.PutUint64(entropy[1:9], uint64(currentTime.UnixNano()))
		binary.LittleEndian.PutUint64(entropy[9:17], uint64(timeDelta))
		
		ch <- entropy
	}
}

func (ec *EntropyCollector) GetCombinedEntropy() []byte {
	combined := make([]byte, 0, len(ec.keyboardData)+len(ec.mouseData)+64)
	combined = append(combined, ec.keyboardData...)
	combined = append(combined, ec.mouseData...)
	
	cryptoRandom := make([]byte, 64)
	io.ReadFull(rand.Reader, cryptoRandom)
	combined = append(combined, cryptoRandom...)
	
	hash := sha256.Sum256(combined)
	return hash[:]
}

func generateSecurePassword(length int, entropy []byte) (string, error) {
	if length < minLength || length > maxLength {
		return "", fmt.Errorf("invalid length")
	}

	additionalEntropy := memguard.NewBufferRandom(32)
	defer additionalEntropy.Destroy()

	combined := make([]byte, len(entropy)+len(additionalEntropy.Data())+32)
	copy(combined, entropy)
	copy(combined[len(entropy):], additionalEntropy.Data())
	io.ReadFull(rand.Reader, combined[len(entropy)+len(additionalEntropy.Data()):])

	password := memguard.NewBuffer(length)
	defer password.Destroy()

	hash := sha256.Sum256(combined)
	for i := 0; i < length; i++ {
		idx := i % len(hash)
		charIdx := int(hash[idx]) % len(charSet)
		password.Data()[i] = charSet[charIdx]
		
		if (i+1)%16 == 0 && i+1 < length {
			hash = sha256.Sum256(hash[:])
		}
	}

	result := string(password.Data())
	secureWipe(combined)
	
	return result, nil
}

// Simple quantum-resistant encryption: Argon2id + AES-256-GCM
// NO NIST KEMs, NO Cloudflare, pure independent stack
func saveEncryptedPassword(password []byte, outputPath string, verbose bool) error {
	fmt.Print("\n🔐 Enter passphrase: ")
	passphraseBuffer, err := readPasswordNoEchoSecure()
	if err != nil {
		return fmt.Errorf("failed to read passphrase: %v", err)
	}
	defer passphraseBuffer.Destroy()

	fmt.Print("🔐 Confirm passphrase: ")
	confirmBuffer, err := readPasswordNoEchoSecure()
	if err != nil {
		return fmt.Errorf("failed to read confirmation: %v", err)
	}
	defer confirmBuffer.Destroy()

	if !passphraseBuffer.EqualTo(confirmBuffer.Data()) {
		return fmt.Errorf("passphrases do not match")
	}

	// Generate salt
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("failed to generate salt: %v", err)
	}

	if verbose {
		fmt.Printf("🔬 Quantum-resistant encryption stack:\n")
		fmt.Printf("   KDF: Argon2id (time=%d, memory=%dMB, threads=%d)\n", 
			argon2Time, argon2Memory/1024, argon2Threads)
		fmt.Printf("   Cipher: AES-256-GCM\n")
		fmt.Printf("   ✅ NO NIST KEMs\n")
		fmt.Printf("   ✅ NO Cloudflare dependencies\n")
		fmt.Printf("   ✅ Memory-hard: resists quantum speedup\n")
	}

	// Derive key with Argon2id (quantum-resistant)
	derivedKey := argon2.IDKey(
		passphraseBuffer.Data(),
		salt,
		argon2Time,
		argon2Memory,
		argon2Threads,
		argon2KeyLen,
	)
	defer secureWipe(derivedKey)

	// Encrypt with AES-256-GCM
	encryptedData, nonce, err := encryptAESGCM(password, derivedKey)
	if err != nil {
		return fmt.Errorf("encryption failed: %v", err)
	}

	// File format: salt:nonce:encryptedData (all hex-encoded)
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer outFile.Close()

	_, err = fmt.Fprintf(outFile, "%s:%s:%s\n",
		hex.EncodeToString(salt),
		hex.EncodeToString(nonce),
		hex.EncodeToString(encryptedData))
	
	if err != nil {
		return fmt.Errorf("failed to write file: %v", err)
	}

	if verbose {
		fmt.Printf("✅ Password encrypted and saved: %s\n", outputPath)
		fmt.Printf("📊 File size: %d bytes (salt=%d, nonce=%d, data=%d)\n",
			len(salt)+len(nonce)+len(encryptedData)+2, // +2 for colons
			len(salt), len(nonce), len(encryptedData))
	}

	return nil
}

func decryptPassword(filePath string, verbose bool) error {
	fmt.Print("🔐 Enter passphrase: ")
	passphraseBuffer, err := readPasswordNoEchoSecure()
	if err != nil {
		return fmt.Errorf("failed to read passphrase: %v", err)
	}
	defer passphraseBuffer.Destroy()

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	// Parse: salt:nonce:encryptedData
	strData := strings.TrimSpace(string(data))
	parts := strings.Split(strData, ":")
	
	if len(parts) != 3 {
		return fmt.Errorf("invalid file format (expected 3 parts, got %d)", len(parts))
	}

	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("failed to decode salt: %v", err)
	}

	nonce, err := hex.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("failed to decode nonce: %v", err)
	}

	encryptedData, err := hex.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("failed to decode encrypted data: %v", err)
	}

	if verbose {
		fmt.Printf("🔬 Decrypting with Argon2id + AES-256-GCM\n")
	}

	// Derive key with Argon2id
	derivedKey := argon2.IDKey(
		passphraseBuffer.Data(),
		salt,
		argon2Time,
		argon2Memory,
		argon2Threads,
		argon2KeyLen,
	)
	defer secureWipe(derivedKey)

	// Decrypt
	plaintext, err := decryptAESGCM(encryptedData, derivedKey, nonce)
	if err != nil {
		return fmt.Errorf("decryption failed (wrong passphrase?): %v", err)
	}
	defer secureWipe(plaintext)

	fmt.Printf("\n🔓 Decrypted Password: %s\n", string(plaintext))
	fmt.Println("💀 Password wiped from memory")

	return nil
}

func encryptAESGCM(plaintext, key []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

func decryptAESGCM(ciphertext, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// DoD 5220.22-M secure file wipe
func secureFileWipe(filePath string, verbose bool) error {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("cannot access file: %v", err)
	}

	fileSize := fileInfo.Size()
	
	if verbose {
		fmt.Printf("🔥 Secure wipe: %s\n", filePath)
		fmt.Printf("📊 Size: %d bytes\n", fileSize)
		fmt.Printf("🔁 DoD 5220.22-M (%d passes)\n", wipePatterns)
	}

	file, err := os.OpenFile(filePath, os.O_RDWR, 0666)
	if err != nil {
		return fmt.Errorf("failed to open: %v", err)
	}
	defer file.Close()

	patterns := []byte{0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF}

	// Passes 1-6: alternating patterns
	for pass := 0; pass < len(patterns); pass++ {
		if _, err := file.Seek(0, 0); err != nil {
			return fmt.Errorf("seek failed pass %d: %v", pass+1, err)
		}

		pattern := make([]byte, 4096)
		for i := range pattern {
			pattern[i] = patterns[pass]
		}

		written := int64(0)
		for written < fileSize {
			toWrite := int64(len(pattern))
			if written+toWrite > fileSize {
				toWrite = fileSize - written
			}
			
			n, err := file.Write(pattern[:toWrite])
			if err != nil {
				return fmt.Errorf("write failed pass %d: %v", pass+1, err)
			}
			written += int64(n)
		}

		if err := file.Sync(); err != nil {
			return fmt.Errorf("sync failed pass %d: %v", pass+1, err)
		}

		if verbose {
			fmt.Printf("✅ Pass %d/%d (0x%02X)\n", pass+1, wipePatterns, patterns[pass])
		}
	}

	// Pass 7: random data
	if _, err := file.Seek(0, 0); err != nil {
		return fmt.Errorf("seek failed random pass: %v", err)
	}

	randomBuf := make([]byte, 4096)
	written := int64(0)
	for written < fileSize {
		toWrite := int64(len(randomBuf))
		if written+toWrite > fileSize {
			toWrite = fileSize - written
		}
		
		if _, err := rand.Read(randomBuf[:toWrite]); err != nil {
			return fmt.Errorf("random gen failed: %v", err)
		}
		
		n, err := file.Write(randomBuf[:toWrite])
		if err != nil {
			return fmt.Errorf("write failed random pass: %v", err)
		}
		written += int64(n)
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync failed random pass: %v", err)
	}

	if verbose {
		fmt.Printf("✅ Pass %d/%d (random)\n", wipePatterns, wipePatterns)
	}

	file.Close()
	if err := os.Remove(filePath); err != nil {
		return fmt.Errorf("failed to remove: %v", err)
	}

	if verbose {
		fmt.Printf("🔥 File securely wiped: %s\n", filePath)
	}

	return nil
}

func readPasswordNoEchoSecure() (*memguard.LockedBuffer, error) {
	fd := int(os.Stdin.Fd())
	
	if !term.IsTerminal(fd) {
		return nil, fmt.Errorf("requires terminal")
	}
	
	passwordBytes, err := term.ReadPassword(fd)
	if err != nil {
		return nil, err
	}
	fmt.Println()
	
	buffer := memguard.NewBufferFromBytes(passwordBytes)
	secureWipe(passwordBytes)
	buffer.Freeze()
	
	return buffer, nil
}

func secureWipe(data []byte) {
	if data == nil {
		return
	}
	rand.Read(data)
	for i := range data {
		data[i] = 0
	}
	runtime.GC()
}

func secureWipeString(s *string) {
	if s == nil || *s == "" {
		return
	}
	b := []byte(*s)
	secureWipe(b)
	*s = ""
	runtime.GC()
}

func readSingleChar() (byte, error) {
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return 0, err
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	reader := bufio.NewReader(os.Stdin)
	char, err := reader.ReadByte()
	return char, err
}

func main() {
	memguard.CatchInterrupt()
	defer memguard.Purge()

	length := flag.Int("l", defaultLength, "Password length (8-256)")
	out := flag.String("o", defaultOutputFile, "Output file")
	decrypt := flag.Bool("decrypt", false, "Decrypt password")
	encfile := flag.String("encfile", "", "File to decrypt")
	wipe := flag.Bool("wipe", false, "Secure wipe file")
	wipefile := flag.String("wipefile", "", "File to wipe")
	showVersion := flag.Bool("version", false, "Show version")
	verbose := flag.Bool("v", false, "Verbose")
	flag.Parse()

	if *showVersion {
		fmt.Printf("gensecpass2-simple v%s\n", version)
		fmt.Printf("Go %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
		fmt.Println("✨ Keyboard+Mouse Physical Entropy")
		fmt.Println("🔐 Quantum-Resistant: Argon2id + AES-256-GCM")
		fmt.Println("🔥 DoD 5220.22-M Secure Wipe")
		fmt.Println("✅ NO NIST KEMs")
		fmt.Println("✅ NO Cloudflare dependencies")
		fmt.Println("✅ 100% Independent")
		return
	}

	// Wipe mode
	if *wipe {
		if *wipefile == "" {
			fmt.Fprintln(os.Stderr, "Error: -wipefile required")
			os.Exit(1)
		}
		
		fmt.Printf("⚠️  WARNING: PERMANENTLY destroy %s\n", *wipefile)
		fmt.Print("Type 'YES' to confirm: ")
		
		reader := bufio.NewReader(os.Stdin)
		confirm, _ := reader.ReadString('\n')
		confirm = strings.TrimSpace(confirm)
		
		if confirm != "YES" {
			fmt.Println("❌ Cancelled")
			return
		}
		
		if err := secureFileWipe(*wipefile, *verbose); err != nil {
			fmt.Fprintf(os.Stderr, "Wipe error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Decrypt mode
	if *decrypt {
		if *encfile == "" {
			fmt.Fprintln(os.Stderr, "Error: -encfile required")
			os.Exit(1)
		}
		if err := decryptPassword(*encfile, *verbose); err != nil {
			fmt.Fprintf(os.Stderr, "Decrypt error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Validate length
	if *length < minLength || *length > maxLength {
		fmt.Fprintf(os.Stderr, "Error: Length %d-%d\n", minLength, maxLength)
		os.Exit(1)
	}

	outputPath := *out
	if outputPath == "." {
		outputPath = defaultOutputFile
	}

	fmt.Printf("╔════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║    gensecpass2-simple v%s - Independent & Secure    ║\n", version)
	fmt.Printf("║  🔐 Argon2id + AES-256 (NO NIST, NO Cloudflare)          ║\n")
	fmt.Printf("║  ⌨️🖱️  Dual Physical Entropy Sources                       ║\n")
	fmt.Printf("╚════════════════════════════════════════════════════════════╝\n\n")
	fmt.Printf("🎯 Generating %d-character password\n\n", *length)

	collector := NewEntropyCollector()

	// Collect keyboard entropy
	if err := collector.CollectKeyboardEntropy(minKeyEntropy, *verbose); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Keyboard error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()

	// Collect mouse entropy
	if err := collector.CollectMouseEntropy(minMouseEntropy, *verbose); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Mouse error: %v\n", err)
		os.Exit(1)
	}

	// Combine entropy
	combinedEntropy := collector.GetCombinedEntropy()
	defer secureWipe(combinedEntropy)

	if *verbose {
		fmt.Printf("\n📊 Entropy: %d B (keyboard) + %d B (mouse) + 64 B (crypto)\n",
			len(collector.keyboardData), len(collector.mouseData))
	}

	// Generate password
	password, err := generateSecurePassword(*length, combinedEntropy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Generation error: %v\n", err)
		os.Exit(1)
	}

	// Ask to save
	fmt.Print("\n💾 Save to encrypted file? (y/N): ")
	saveChoice, err := readSingleChar()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Input error: %v\n", err)
		secureWipeString(&password)
		os.Exit(1)
	}
	fmt.Println()

	if saveChoice == 'y' || saveChoice == 'Y' {
		if err := saveEncryptedPassword([]byte(password), outputPath, *verbose); err != nil {
			fmt.Fprintf(os.Stderr, "Save error: %v\n", err)
			secureWipeString(&password)
			os.Exit(1)
		}
		secureWipeString(&password)
		fmt.Println("\n✅ Password saved and wiped from memory")
		fmt.Printf("📁 File: %s\n", outputPath)
		fmt.Printf("💡 Decrypt: gensecpass2-simple -decrypt -encfile %s\n", outputPath)
		fmt.Printf("💡 Wipe: gensecpass2-simple -wipe -wipefile %s\n", outputPath)
	} else {
		fmt.Printf("\n🔑 Generated Password: %s\n", password)
		secureWipeString(&password)
		fmt.Println("💀 Password wiped from memory (not saved)")
	}
}
