package main

/*
#cgo LDFLAGS: -lX11
#include <X11/Xlib.h>
#include <stdlib.h>
*/
import "C"

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"filippo.io/age"
	"github.com/awnumar/memguard"
	"golang.org/x/term"
)

const (
	version           = "1.0.0"
	defaultLength     = 16
	minLength         = 8
	maxLength         = 128
	charSet           = "abcdefghijklmnopqrstuvwxyz" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"0123456789" +
		"!@#$%^&*()-_=+[]{}|;:,.<>?/"
	defaultOutputFile = "password.txt.age"
	baseMouseEntropy  = 64 // fixed 64 bytes for optimal speed/security balance
	mouseTimeout      = 120 * time.Second // increased timeout to 2 minutes
	mouseWarningTime  = 30 * time.Second  // warning time increased

	// Placeholder security parameters (will be replaced with real McEliece)
	placeholderKeySize = 32 // 256-bit key for AES-256-GCM placeholder
)

func main() {
	// Initialize memguard
	defer memguard.Purge()

	// Parse command line flags
	length := flag.Int("l", defaultLength, "Password length")
	out := flag.String("o", defaultOutputFile, "Output file path (supports '.' for current directory)")
	decrypt := flag.Bool("decrypt", false, "Decrypt and display password from encrypted file")
	encfile := flag.String("encfile", "", "Encrypted file path to decrypt")
	showVersion := flag.Bool("version", false, "Show version information")
	verbose := flag.Bool("v", false, "Verbose output")
	flag.Parse()

	if *showVersion {
		fmt.Printf("gensecpass version %s\n", version)
		fmt.Printf("Built with Go %s for %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return
	}

	// Handle decrypt mode
	if *decrypt {
		if *encfile == "" {
			fmt.Fprintln(os.Stderr, "Error: Use -encfile <file.age> to specify the encrypted file to decrypt.")
			os.Exit(1)
		}
		if err := decryptPassword(*encfile, *verbose); err != nil {
			fmt.Fprintf(os.Stderr, "Decryption error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Validate password length
	if *length < minLength || *length > maxLength {
		fmt.Fprintf(os.Stderr, "Error: Password length must be between %d and %d characters.\n", minLength, maxLength)
		os.Exit(1)
	}

	// Handle output path
	outputPath := *out
	if outputPath == "." {
		outputPath = defaultOutputFile
	}

	fmt.Printf("gensecpass v%s - Quantum-Safe Password Generator\n", version)
	fmt.Printf("🔒 4-Layer Security: Mouse + MemGuard + PostQuantum + Age\n")
	fmt.Printf("⚠️  Note: Using AES-256-GCM placeholder for quantum layer (McEliece coming soon)\n")
	fmt.Printf("Generating %d-character password...\n\n", *length)

	// Calculate required mouse entropy based on password length
	requiredMouseEntropy := calculateRequiredEntropy(*length)
	
	// Mandatory mouse entropy collection
	fmt.Printf("🖱️  MANDATORY: Move your mouse to collect entropy...\n")
	fmt.Printf("Password length: %d characters\n", *length)
	fmt.Printf("Required mouse entropy: %d bytes\n", requiredMouseEntropy)
	fmt.Printf("Timeout: %v | Warning after: %v of inactivity\n\n", mouseTimeout, mouseWarningTime)
	
	mouseEntropy, err := collectMouseEntropy(requiredMouseEntropy, mouseTimeout, *verbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error collecting mouse entropy: %v\n", err)
		fmt.Fprintln(os.Stderr, "Mouse entropy is mandatory for secure password generation.")
		os.Exit(1)
	}

	if *verbose {
		fmt.Printf("Successfully collected %d bytes of mouse entropy.\n", len(mouseEntropy))
	}

	// Generate password using memguard for secure storage
	password, err := generateSecurePassword(*length, mouseEntropy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating password: %v\n", err)
		// mouseEntropy will be cleaned by defer memguard.Purge()
		os.Exit(1)
	}

	// Clean up mouse entropy as it's no longer needed
	// (memguard.Purge() will handle this at program exit)

	// Ask user if they want to save the password
	fmt.Print("\nDo you want to save the password to an encrypted file? (y/N): ")
	saveChoice, err := readSingleChar()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		password.Destroy()
		os.Exit(1)
	}

	if saveChoice == 'y' || saveChoice == 'Y' {
		// Save encrypted password
		if err := saveEncryptedPassword(password, outputPath, *verbose); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving encrypted password: %v\n", err)
			password.Destroy()
			os.Exit(1)
		}
		// Secure destroy of password from memory
		password.Destroy()
		fmt.Println("\nPassword saved securely. Original password destroyed from memory.")
	} else {
		// Display password on screen only
		fmt.Printf("\nGenerated Password: %s\n", string(password.Bytes()))
		
		fmt.Println("\nPassword displayed only (not saved to disk).")
		// Secure destroy of password from memory
		password.Destroy()
		fmt.Println("Password destroyed from memory.")
	}
}

// calculateRequiredEntropy determines how much mouse entropy is needed based on password length
func calculateRequiredEntropy(passwordLength int) int {
	// Fixed 64 bytes for optimal speed/security balance
	// crypto/rand provides the main security, mouse entropy is additional randomness
	return baseMouseEntropy
}

// collectMouseEntropy collects entropy from mouse movement with progress indicator and warnings
// Uses X11 coordinate polling like mouse_entropy project
func collectMouseEntropy(minBytes int, timeout time.Duration, verbose bool) ([]byte, error) {
	// Open X11 display
	display := C.XOpenDisplay(nil)
	if display == nil {
		return nil, fmt.Errorf("cannot open X11 display (is DISPLAY set?)")
	}
	defer C.XCloseDisplay(display)

	if verbose {
		fmt.Printf("Using X11 coordinate polling for mouse entropy\n")
	}

	// Get root window
	rootWindow := C.XDefaultRootWindow(display)

	// Allocate buffer for entropy collection (double size for better sampling like mouse_entropy)
	buf := make([]byte, minBytes*2)
	collected := 0
	start := time.Now()
	lastProgress := 0
	lastMovement := time.Now()
	warningShown := false
	warningCount := 0

	var lastX, lastY C.int
	const sampleDelay = 80 * time.Millisecond // 80ms for optimal speed/security balance

	fmt.Print("Progress: [")
	for i := 0; i < 30; i++ { // Wider progress bar
		fmt.Print(" ")
	}
	fmt.Print("] 0%")
	fmt.Printf("\n💡 TIP: Move your mouse in various patterns (circles, zigzags, random movements)\n")
	fmt.Printf("🎯 Target: %d bytes | Current: 0 bytes\n", minBytes)

	lastSample := time.Now()

	for time.Since(start) < timeout && collected < minBytes {
		var rootReturn, childReturn C.Window
		var rootX, rootY, winX, winY C.int
		var mask C.uint

		// Query mouse pointer position
		C.XQueryPointer(display, rootWindow, &rootReturn, &childReturn,
			&rootX, &rootY, &winX, &winY, &mask)

		currentTime := time.Now()
		timeSinceLastSample := currentTime.Sub(lastSample)

		// Check if enough time has passed and mouse has moved
		if timeSinceLastSample > sampleDelay && (rootX != lastX || rootY != lastY) {
			// Generate one random byte
			var randomByte byte
			if _, err := rand.Read([]byte{randomByte}); err != nil {
				return nil, fmt.Errorf("failed to generate random byte: %v", err)
			}

			// Combine mouse coordinates, timestamp and random byte using XOR
			// This is the same approach as mouse_entropy_linux.c
			timeNano := currentTime.UnixNano()
			entropyByte := byte(rootX) ^ byte(rootY) ^ byte(timeNano&0xFF) ^ randomByte

			buf[collected] = entropyByte
			collected++

			lastMovement = currentTime
			lastSample = currentTime
			lastX = rootX
			lastY = rootY
			warningShown = false
			warningCount = 0

			// Update progress bar every few bytes to reduce flicker
			progress := (collected * 1000) / minBytes
			if progress > lastProgress+5 { // Update every 0.5%
				fmt.Print("\r\033[K") // Clear entire line
				fmt.Print("Progress: [")
				filled := (collected * 30) / minBytes
				for i := 0; i < 30; i++ {
					if i < filled {
						fmt.Print("=")
					} else if i == filled && collected < minBytes {
						fmt.Print(">")
					} else {
						fmt.Print(" ")
					}
				}
				progressPercent := float64(collected) / float64(minBytes) * 100
				bytesPerSec := float64(collected) / time.Since(start).Seconds()
				eta := time.Duration(float64(minBytes-collected)/bytesPerSec) * time.Second

				fmt.Printf("] %.1f%% (%d/%d bytes) | %.0f B/s | ETA: %v",
					progressPercent, collected, minBytes, bytesPerSec, eta.Round(time.Second))
				lastProgress = progress
			}

			if collected >= minBytes {
				break
			}
		} else {
			// Check if we need to show warning
			timeSinceMovement := time.Since(lastMovement)
			if timeSinceMovement > mouseWarningTime {
				if !warningShown || timeSinceMovement > time.Duration(warningCount+1)*mouseWarningTime {
					warningCount++
					fmt.Printf("\r\033[K") // Clear line
					fmt.Printf("⚠️  WARNING #%d: No mouse movement for %v! Keep moving to continue...\n",
						warningCount, timeSinceMovement.Round(time.Second))
					fmt.Printf("📊 Progress: %d/%d bytes (%.1f%%) | Time elapsed: %v\n",
						collected, minBytes, float64(collected)/float64(minBytes)*100, time.Since(start).Round(time.Second))
					fmt.Print("Progress: [")
					filled := (collected * 30) / minBytes
					for i := 0; i < 30; i++ {
						if i < filled {
							fmt.Print("=")
						} else {
							fmt.Print(" ")
						}
					}
					fmt.Printf("] %.1f%%", float64(collected)/float64(minBytes)*100)
					warningShown = true
				}
			}
		}

		time.Sleep(10 * time.Millisecond)
	}

	fmt.Print("\r\033[K") // Clear line
	totalTime := time.Since(start)
	avgSpeed := float64(collected) / totalTime.Seconds()
	fmt.Printf("✅ Entropy collection completed!\n")
	fmt.Printf("📊 Collected: %d bytes in %v (avg: %.0f B/s)\n", collected, totalTime.Round(time.Millisecond), avgSpeed)
	fmt.Printf("🔐 Entropy quality: %s\n", getEntropyQuality(collected, totalTime))

	if collected < minBytes {
		return nil, fmt.Errorf("insufficient mouse entropy collected: got %d bytes, need %d bytes", collected, minBytes)
	}

	return buf[:collected], nil
}

// getEntropyQuality provides feedback on the quality of collected entropy
func getEntropyQuality(bytes int, duration time.Duration) string {
	bytesPerSec := float64(bytes) / duration.Seconds()
	
	if bytesPerSec > 100 {
		return "Excellent (high activity)"
	} else if bytesPerSec > 50 {
		return "Very Good (good activity)"
	} else if bytesPerSec > 25 {
		return "Good (moderate activity)"
	} else if bytesPerSec > 10 {
		return "Fair (low activity)"
	} else {
		return "Poor (very low activity)"
	}
}

// generateSecurePassword creates a cryptographically secure password using fused entropy
func generateSecurePassword(length int, mouseEntropy []byte) (*memguard.LockedBuffer, error) {
	charset := []rune(charSet)
	charsetLen := len(charset)
	
	// Create secure buffer for the password
	passwordBuf := memguard.NewBuffer(length)
	if passwordBuf.Size() == 0 {
		return nil, fmt.Errorf("failed to create secure buffer of size %d", length)
	}

	// Create fused entropy source by combining crypto/rand with mouse entropy
	// Use 4 bytes per character instead of 8 to avoid overflow
	fusedEntropy, err := createFusedEntropy(mouseEntropy, length*4) 
	if err != nil {
		passwordBuf.Destroy()
		return nil, fmt.Errorf("failed to create fused entropy: %v", err)
	}
	defer secureWipe(fusedEntropy)

	// Generate password characters using fused entropy
	for i := 0; i < length; i++ {
		// Use 4 bytes of fused entropy per character
		entropyOffset := i * 4
		if entropyOffset+4 > len(fusedEntropy) {
			passwordBuf.Destroy()
			return nil, fmt.Errorf("insufficient fused entropy: need %d, have %d", entropyOffset+4, len(fusedEntropy))
		}

		// Convert 4 bytes of entropy to an integer
		entropyBytes := fusedEntropy[entropyOffset : entropyOffset+4]
		var entropyInt uint32 = 0
		for j, b := range entropyBytes {
			entropyInt |= uint32(b) << (8 * j)
		}

		// Map to character set
		idx := int(entropyInt) % charsetLen
		passwordBuf.Bytes()[i] = byte(charset[idx])
	}

	// Make it immutable for safety
	passwordBuf.Freeze()
	
	return passwordBuf, nil
}

// createFusedEntropy combines crypto/rand and mouse entropy using SHA-256
func createFusedEntropy(mouseEntropy []byte, requiredBytes int) ([]byte, error) {
	if len(mouseEntropy) == 0 {
		return nil, fmt.Errorf("no mouse entropy provided")
	}

	// We'll create multiple rounds of entropy and hash them together
	rounds := (requiredBytes + 31) / 32 // 32 bytes per SHA-256 round
	result := make([]byte, 0, rounds*32)

	for round := 0; round < rounds; round++ {
		hasher := sha256.New()
		
		// Add round number to prevent identical hashes
		roundBytes := make([]byte, 4)
		roundBytes[0] = byte(round)
		roundBytes[1] = byte(round >> 8)
		roundBytes[2] = byte(round >> 16)
		roundBytes[3] = byte(round >> 24)
		hasher.Write(roundBytes)

		// Add crypto/rand entropy (32 bytes per round)
		cryptoBytes := make([]byte, 32)
		if _, err := rand.Read(cryptoBytes); err != nil {
			return nil, fmt.Errorf("crypto/rand failed: %v", err)
		}
		hasher.Write(cryptoBytes)
		
		// Securely wipe crypto bytes after use
		defer secureWipe(cryptoBytes)

		// Add mouse entropy (cycle through it if needed)
		for i := 0; i < 32; i++ {
			mouseIdx := (round*32 + i) % len(mouseEntropy)
			hasher.Write([]byte{mouseEntropy[mouseIdx]})
		}

		// Add current timestamp as additional entropy
		timestamp := time.Now().UnixNano()
		timestampBytes := make([]byte, 8)
		for i := 0; i < 8; i++ {
			timestampBytes[i] = byte(timestamp >> (8 * i))
		}
		hasher.Write(timestampBytes)

		// Generate hash and append to result
		hash := hasher.Sum(nil)
		result = append(result, hash...)
	}

	// Return exactly the number of bytes requested
	if len(result) > requiredBytes {
		// Securely wipe the excess
		secureWipe(result[requiredBytes:])
		result = result[:requiredBytes]
	}

	return result, nil
}

// saveEncryptedPassword encrypts and saves password using 4-layer security
func saveEncryptedPassword(passwordBuffer *memguard.LockedBuffer, outputPath string, verbose bool) error {
	// Create directory if needed
	dir := filepath.Dir(outputPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create directory: %v", err)
		}
	}

	// Get passphrase for encryption using memguard
	fmt.Print("Enter passphrase for encryption: ")
	passphraseBuffer, err := readPasswordNoEchoSecure()
	if err != nil {
		return fmt.Errorf("failed to read passphrase: %v", err)
	}
	defer passphraseBuffer.Destroy()

	if passphraseBuffer.Size() == 0 {
		return fmt.Errorf("empty passphrase not allowed")
	}

	fmt.Print("Confirm passphrase: ")
	confirmBuffer, err := readPasswordNoEchoSecure()
	if err != nil {
		return fmt.Errorf("failed to read confirmation: %v", err)
	}
	defer confirmBuffer.Destroy()

	// Compare passphrases securely
	if passphraseBuffer.Size() != confirmBuffer.Size() {
		return fmt.Errorf("passphrases do not match")
	}
	
	// Constant-time comparison
	passphraseBytes := passphraseBuffer.Bytes()
	confirmBytes := confirmBuffer.Bytes()
	match := true
	for i := 0; i < len(passphraseBytes) && i < len(confirmBytes); i++ {
		if passphraseBytes[i] != confirmBytes[i] {
			match = false
		}
	}
	if !match {
		return fmt.Errorf("passphrases do not match")
	}

	if verbose {
		fmt.Println("🔐 Starting 4-layer encryption process...")
		fmt.Println("  Layer 1: ✅ Mouse entropy already collected")
		fmt.Println("  Layer 2: ✅ MemGuard secure storage active")
		fmt.Println("  Layer 3: 🔒 Applying quantum-safe pre-encryption (AES-256-GCM placeholder)...")
	}

	// Layer 3: Quantum-safe pre-encryption (placeholder)
	quantumProtectedData, err := applyQuantumSafeLayer(passwordBuffer.Bytes(), verbose)
	if err != nil {
		return fmt.Errorf("quantum-safe layer failed: %v", err)
	}
	defer secureWipe(quantumProtectedData)

	if verbose {
		fmt.Println("  Layer 4: 📦 Applying Age final encryption...")
	}

	// Layer 4: Age final encryption
	recipient, err := age.NewScryptRecipient(string(passphraseBytes))
	if err != nil {
		return fmt.Errorf("failed to create age recipient: %v", err)
	}

	// Create temporary file first for atomic write
	tempPath := outputPath + ".tmp"
	tempFile, err := os.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %v", err)
	}

	// Encrypt with age
	w, err := age.Encrypt(tempFile, recipient)
	if err != nil {
		tempFile.Close()
		os.Remove(tempPath)
		return fmt.Errorf("failed to initialize age encryption: %v", err)
	}

	if _, err := w.Write(quantumProtectedData); err != nil {
		w.Close()
		tempFile.Close()
		os.Remove(tempPath)
		return fmt.Errorf("failed to write encrypted data: %v", err)
	}

	if err := w.Close(); err != nil {
		tempFile.Close()
		os.Remove(tempPath)
		return fmt.Errorf("failed to finalize encryption: %v", err)
	}

	if err := tempFile.Sync(); err != nil {
		tempFile.Close()
		os.Remove(tempPath)
		return fmt.Errorf("failed to sync file: %v", err)
	}

	tempFile.Close()

	// Atomic move
	if err := os.Rename(tempPath, outputPath); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("failed to move file to final location: %v", err)
	}

	// Calculate and display file hash
	hash, err := calculateFileSHA256(outputPath)
	if err != nil {
		fmt.Printf("Warning: Could not calculate file hash: %v\n", err)
	} else {
		fmt.Printf("🔒 4-layer encrypted file saved: %s\n", outputPath)
		fmt.Printf("📊 File SHA-256 fingerprint: %s\n", hash)
		if verbose {
			fmt.Println("  Layer 3: 🔒 Quantum-safe protection applied")
			fmt.Println("  Layer 4: 📦 Age encryption completed")
		}
	}

	return nil
}

// decryptPassword decrypts and displays password using 4-layer security
func decryptPassword(encFilePath string, verbose bool) error {
	file, err := os.Open(encFilePath)
	if err != nil {
		return fmt.Errorf("failed to open encrypted file: %v", err)
	}
	defer file.Close()

	// Ask for passphrase using memguard
	fmt.Print("Enter passphrase for decryption: ")
	passphraseBuffer, err := readPasswordNoEchoSecure()
	if err != nil {
		return fmt.Errorf("failed to read passphrase: %v", err)
	}
	defer passphraseBuffer.Destroy()

	identity, err := age.NewScryptIdentity(string(passphraseBuffer.Bytes()))
	if err != nil {
		return fmt.Errorf("failed to create age identity: %v", err)
	}

	if verbose {
		fmt.Println("🔓 Starting 4-layer decryption process...")
		fmt.Println("  Layer 4: 📦 Decrypting Age layer...")
	}

	// Layer 4: Age decryption
	r, err := age.Decrypt(file, identity)
	if err != nil {
		return fmt.Errorf("failed to decrypt age layer (wrong passphrase or corrupted file): %v", err)
	}

	// Read quantum-protected data
	quantumData, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("failed to read decrypted data: %v", err)
	}

	if verbose {
		fmt.Println("  Layer 3: 🔒 Decrypting quantum-safe layer (AES-256-GCM placeholder)...")
	}

	// Layer 3: Quantum-safe decryption
	passwordData, err := removeQuantumSafeLayer(quantumData, verbose)
	if err != nil {
		secureWipe(quantumData)
		return fmt.Errorf("quantum-safe decryption failed: %v", err)
	}
	defer secureWipe(passwordData)

	// Secure wipe of intermediate data
	secureWipe(quantumData)

	if verbose {
		fmt.Println("  Layer 2: ✅ Using MemGuard for secure display")
		fmt.Println("  Layer 1: ✅ Original mouse entropy was used in generation")
	}

	// Create secure buffer for the decrypted password
	passwordBuffer := memguard.NewBufferFromBytes(passwordData)
	defer passwordBuffer.Destroy()

	// Display password
	fmt.Printf("🔓 Decrypted Password: %s\n", string(passwordBuffer.Bytes()))

	if verbose {
		fmt.Println("🔒 4-layer decryption completed successfully!")
	}

	return nil
}

// applyQuantumSafeLayer applies quantum-safe pre-encryption (AES-256-GCM placeholder for now)
func applyQuantumSafeLayer(passwordData []byte, verbose bool) ([]byte, error) {
	if verbose {
		fmt.Printf("    🔒 Generating quantum-safe encryption key...\n")
	}

	// Generate a random key for AES-256-GCM
	key := make([]byte, placeholderKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate quantum-safe key: %v", err)
	}
	defer secureWipe(key)

	// Encrypt the password with AES-256-GCM
	encryptedPassword, err := encryptWithAESGCM(passwordData, key)
	if err != nil {
		return nil, fmt.Errorf("quantum-safe encryption failed: %v", err)
	}

	// For the placeholder, we'll prepend the key (in real McEliece, this key would be encrypted)
	// WARNING: This is NOT quantum-safe! It's just a placeholder.
	result := make([]byte, 0, len(key)+len(encryptedPassword))
	result = append(result, key...)
	result = append(result, encryptedPassword...)

	if verbose {
		fmt.Printf("    🔒 Quantum-safe layer complete (%d total bytes)\n", len(result))
		fmt.Printf("    ⚠️  PLACEHOLDER: Key stored in plaintext (not quantum-safe yet!)\n")
	}

	return result, nil
}

// removeQuantumSafeLayer removes quantum-safe pre-encryption (AES-256-GCM placeholder)
func removeQuantumSafeLayer(quantumData []byte, verbose bool) ([]byte, error) {
	if len(quantumData) < placeholderKeySize {
		return nil, fmt.Errorf("invalid quantum data: too short")
	}

	// Extract key and encrypted data (PLACEHOLDER ONLY!)
	key := quantumData[:placeholderKeySize]
	encryptedPassword := quantumData[placeholderKeySize:]

	if verbose {
		fmt.Printf("    🔒 Extracting quantum-safe components (key:%d, data:%d bytes)\n",
			len(key), len(encryptedPassword))
		fmt.Printf("    ⚠️  PLACEHOLDER: Reading key from plaintext (not quantum-safe yet!)\n")
	}

	// Decrypt the password with AES-256-GCM
	passwordData, err := decryptWithAESGCM(encryptedPassword, key)
	if err != nil {
		return nil, fmt.Errorf("quantum-safe decryption failed: %v", err)
	}

	if verbose {
		fmt.Printf("    🔒 Password decrypted with quantum-safe layer\n")
	}

	return passwordData, nil
}

// encryptWithAESGCM encrypts data using AES-256-GCM
func encryptWithAESGCM(plaintext, key []byte) ([]byte, error) {
	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Encrypt data
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Prepend nonce to ciphertext
	result := make([]byte, 0, len(nonce)+len(ciphertext))
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

// decryptWithAESGCM decrypts data using AES-256-GCM  
func decryptWithAESGCM(ciphertext, key []byte) ([]byte, error) {
	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	// Check minimum length
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce := ciphertext[:gcm.NonceSize()]
	encryptedData := ciphertext[gcm.NonceSize():]

	// Decrypt data
	plaintext, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %v", err)
	}

	return plaintext, nil
}

// readPasswordNoEchoSecure reads password without echo using memguard for secure storage
func readPasswordNoEchoSecure() (*memguard.LockedBuffer, error) {
	fd := int(os.Stdin.Fd())
	
	if !term.IsTerminal(fd) {
		return nil, fmt.Errorf("password input requires a terminal")
	}
	
	passwordBytes, err := term.ReadPassword(fd)
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %v", err)
	}
	fmt.Println() // Add newline after password input
	
	// Create secure buffer and immediately wipe the original
	buffer := memguard.NewBufferFromBytes(passwordBytes)
	
	// Make it immutable
	buffer.Freeze()
	
	return buffer, nil
}

// Secure memory cleanup utilities
func secureWipe(data []byte) {
	if data == nil {
		return
	}
	// Overwrite with random data first
	rand.Read(data)
	// Then zero out
	for i := range data {
		data[i] = 0
	}
	runtime.GC() // Encourage garbage collection
}

func secureWipeString(s *string) {
	if s == nil || *s == "" {
		return
	}
	// Convert to slice and wipe
	b := []byte(*s)
	secureWipe(b)
	*s = ""
	runtime.GC()
}

// readSingleChar reads a single character from stdin
func readSingleChar() (rune, error) {
	fd := int(os.Stdin.Fd())
	
	if !term.IsTerminal(fd) {
		// If not a terminal, read a line normally
		var input string
		_, err := fmt.Scanln(&input)
		if err != nil {
			return 0, err
		}
		if len(input) > 0 {
			return rune(input[0]), nil
		}
		return 0, fmt.Errorf("no input received")
	}
	
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return 0, err
	}
	defer term.Restore(fd, oldState)
	
	buf := make([]byte, 1)
	_, err = os.Stdin.Read(buf)
	if err != nil {
		return 0, err
	}
	
	fmt.Printf("%c\n", buf[0]) // Echo the character
	return rune(buf[0]), nil
}

// calculateFileSHA256 computes SHA-256 hash of a file
func calculateFileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// readPasswordNoEcho reads password without echo (legacy function for compatibility)
func readPasswordNoEcho() (string, error) {
	fd := int(os.Stdin.Fd())
	
	// Check if stdin is a terminal
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("password input requires a terminal")
	}
	
	passwordBytes, err := term.ReadPassword(fd)
	if err != nil {
		return "", fmt.Errorf("failed to read password: %v", err)
	}
	
	return string(passwordBytes), nil
}
