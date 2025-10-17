package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"
	"github.com/awnumar/memguard"
	"golang.org/x/term"
)

const (
	version           = "2.1.0"
	minLength         = 8
	maxLength         = 256
	defaultLength     = 16
	charSet           = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/"
	defaultOutputFile = "password.txt.age"
	challenge1Target  = 128 // bytes di entropia - challenge 1 (veloce)
	challenge2Target  = 256 // bytes di entropia - challenge 2 (ritmico)
	entropyTimeout    = 90 * time.Second
	wipePassCount     = 7 // DoD 5220.22-M standard
)

type EntropySource struct {
	data      []byte
	hash      []byte
	startTime time.Time
	timings   []int64 // nanosecondi tra pressioni tasti
}

func NewEntropySource() *EntropySource {
	return &EntropySource{
		data:      make([]byte, 0, 512),
		timings:   make([]int64, 0, 256),
		startTime: time.Now(),
	}
}

func (es *EntropySource) AddByte(b byte, timestamp int64) {
	es.data = append(es.data, b)
	
	// Aggiungi timing se non è il primo byte
	if len(es.timings) > 0 {
		delta := timestamp - es.timings[len(es.timings)-1]
		// Converti delta in bytes (8 bytes)
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, uint64(delta))
		es.data = append(es.data, buf...)
	}
	
	es.timings = append(es.timings, timestamp)
}

func (es *EntropySource) AddTimestamp() {
	now := time.Now().UnixNano()
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(now))
	es.data = append(es.data, buf...)
}

func (es *EntropySource) Finalize() {
	// Hash finale di tutti i dati + timings
	h := sha256.Sum256(es.data)
	es.hash = h[:]
}

func (es *EntropySource) Size() int {
	return len(es.data)
}

func (es *EntropySource) TimingStats() (avgDelta, stdDev float64) {
	if len(es.timings) < 2 {
		return 0, 0
	}

	// Calcola media dei delta
	var sum int64
	deltas := make([]int64, len(es.timings)-1)
	for i := 1; i < len(es.timings); i++ {
		delta := es.timings[i] - es.timings[i-1]
		deltas[i-1] = delta
		sum += delta
	}
	avgDelta = float64(sum) / float64(len(deltas))

	// Calcola deviazione standard
	var variance float64
	for _, delta := range deltas {
		diff := float64(delta) - avgDelta
		variance += diff * diff
	}
	variance /= float64(len(deltas))
	stdDev = float64(int64(variance)) // sqrt approssimato

	return avgDelta / 1000000, stdDev / 1000000 // converti in millisecondi
}

// Challenge 1: Digitazione VELOCE e CAOTICA
func collectChallenge1Entropy(target int, verbose bool) (*EntropySource, error) {
	es := NewEntropySource()
	
	fmt.Println("\n⚡ CHALLENGE 1: CHAOTIC TYPING")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("📊 Target: %d bytes\n", target)
	fmt.Println("⏱️  Timeout: 90 seconds")
	fmt.Println("💡 Type FAST and RANDOMLY:")
	fmt.Println("   • Slam the keyboard chaotically")
	fmt.Println("   • Mix letters, numbers, symbols")
	fmt.Println("   • Don't think, just type!")
	fmt.Println("   • The more chaotic, the better!")
	fmt.Println("✅ Press ENTER when done\n")

	// Imposta terminal in raw mode
	oldState, err := term.MakeRaw(int(syscall.Stdin))
	if err != nil {
		return nil, fmt.Errorf("failed to set raw mode: %w", err)
	}
	defer term.Restore(int(syscall.Stdin), oldState)

	reader := bufio.NewReader(os.Stdin)
	done := make(chan bool)
	timeout := time.After(entropyTimeout)

	go func() {
		lastUpdate := time.Now()
		
		for {
			char, err := reader.ReadByte()
			if err != nil {
				break
			}

			currentTime := time.Now().UnixNano()

			// ENTER per finire
			if char == 0x0D || char == 0x0A {
				if es.Size() >= target {
					done <- true
					return
				}
				continue
			}

			// Ignora caratteri di controllo (tranne ESC, TAB)
			if char < 32 && char != 27 && char != 9 {
				continue
			}

			// Aggiungi byte con timestamp
			es.AddByte(char, currentTime)

			// Mostra progresso
			if time.Since(lastUpdate) > 100*time.Millisecond {
				progress := float64(es.Size()) * 100.0 / float64(target)
				if progress > 100 {
					progress = 100
				}
				
				// Calcola WPM (words per minute) approssimato
				elapsed := time.Since(es.startTime).Seconds()
				wpm := int((float64(len(es.timings)) / 5) / elapsed * 60)
				
				fmt.Printf("\r🔄 Progress: %.1f%% (%d/%d bytes) | Speed: ~%d WPM", 
					progress, es.Size(), target, wpm)
				lastUpdate = time.Now()

				if es.Size() >= target {
					fmt.Println()
					done <- true
					return
				}
			}
		}
	}()

	select {
	case <-done:
		fmt.Println("✅ Challenge 1 completed!")
	case <-timeout:
		if es.Size() < target/2 {
			return nil, fmt.Errorf("insufficient entropy collected (timeout)")
		}
		fmt.Println("\n⏱️  Timeout reached, using collected data")
	}

	// Finalizza con hash
	es.Finalize()

	if verbose {
		avgDelta, stdDev := es.TimingStats()
		fmt.Printf("📊 Collected: %d bytes\n", es.Size())
		fmt.Printf("⌨️  Keystrokes: %d\n", len(es.timings))
		fmt.Printf("⏱️  Avg timing: %.2f ms (±%.2f ms)\n", avgDelta, stdDev)
		fmt.Printf("🔐 Hash: %x...\n", es.hash[:8])
	}

	return es, nil
}

// Challenge 2: Digitazione RITMICA con PAUSE
func collectChallenge2Entropy(target int, verbose bool) (*EntropySource, error) {
	es := NewEntropySource()

	fmt.Println("\n🎵 CHALLENGE 2: RHYTHMIC TYPING")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("📊 Target: %d bytes\n", target)
	fmt.Println("⏱️  Timeout: 90 seconds")
	fmt.Println("💡 Type with VARYING rhythm:")
	fmt.Println("   • Type... pause... type quickly... pause")
	fmt.Println("   • Short bursts, then long pauses")
	fmt.Println("   • Irregular patterns, unpredictable timing")
	fmt.Println("   • Think of it as musical rhythm")
	fmt.Println("✅ Press ENTER when done\n")

	// Imposta terminal in raw mode
	oldState, err := term.MakeRaw(int(syscall.Stdin))
	if err != nil {
		return nil, fmt.Errorf("failed to set raw mode: %w", err)
	}
	defer term.Restore(int(syscall.Stdin), oldState)

	reader := bufio.NewReader(os.Stdin)
	done := make(chan bool)
	timeout := time.After(entropyTimeout)

	go func() {
		lastUpdate := time.Now()
		lastKeyTime := time.Now().UnixNano()
		var lastDelta int64
		
		for {
			char, err := reader.ReadByte()
			if err != nil {
				break
			}

			currentTime := time.Now().UnixNano()
			delta := currentTime - lastKeyTime

			// ENTER per finire
			if char == 0x0D || char == 0x0A {
				if es.Size() >= target {
					done <- true
					return
				}
				continue
			}

			// Ignora caratteri di controllo
			if char < 32 && char != 27 && char != 9 {
				continue
			}

			// Aggiungi byte con timestamp
			es.AddByte(char, currentTime)

			// Feedback visivo sulla variazione del ritmo
			var rhythmIndicator string
			if len(es.timings) > 1 {
				if delta > lastDelta*2 {
					rhythmIndicator = "🐌 SLOW"
				} else if delta < lastDelta/2 {
					rhythmIndicator = "⚡ FAST"
				} else {
					rhythmIndicator = "➡️  STEADY"
				}
			}

			lastDelta = delta
			lastKeyTime = currentTime

			// Mostra progresso con feedback ritmico
			if time.Since(lastUpdate) > 100*time.Millisecond {
				progress := float64(es.Size()) * 100.0 / float64(target)
				if progress > 100 {
					progress = 100
				}
				
				deltaMs := delta / 1000000 // converti in millisecondi
				fmt.Printf("\r🔄 Progress: %.1f%% (%d/%d bytes) | Rhythm: %s (%dms)", 
					progress, es.Size(), target, rhythmIndicator, deltaMs)
				lastUpdate = time.Now()

				if es.Size() >= target {
					fmt.Println()
					done <- true
					return
				}
			}
		}
	}()

	select {
	case <-done:
		fmt.Println("✅ Challenge 2 completed!")
	case <-timeout:
		if es.Size() < target/2 {
			return nil, fmt.Errorf("insufficient entropy collected (timeout)")
		}
		fmt.Println("\n⏱️  Timeout reached, using collected data")
	}

	// Finalizza con hash
	es.Finalize()

	if verbose {
		avgDelta, stdDev := es.TimingStats()
		fmt.Printf("📊 Collected: %d bytes\n", es.Size())
		fmt.Printf("⌨️  Keystrokes: %d\n", len(es.timings))
		fmt.Printf("⏱️  Avg timing: %.2f ms (±%.2f ms)\n", avgDelta, stdDev)
		fmt.Printf("🎵 Rhythm variance: %.2f ms\n", stdDev)
		fmt.Printf("🔐 Hash: %x...\n", es.hash[:8])
	}

	return es, nil
}

// Combina le sorgenti di entropia
func combineEntropy(challenge1, challenge2 *EntropySource, verbose bool) ([]byte, error) {
	if verbose {
		fmt.Println("\n🔀 COMBINING ENTROPY SOURCES")
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	}

	// Crea buffer combinato
	combined := make([]byte, 0, len(challenge1.hash)+len(challenge2.hash)+32)
	combined = append(combined, challenge1.hash...)
	combined = append(combined, challenge2.hash...)

	// Aggiungi crypto/rand
	cryptoBytes := make([]byte, 32)
	if _, err := rand.Read(cryptoBytes); err != nil {
		return nil, fmt.Errorf("crypto/rand failed: %w", err)
	}
	combined = append(combined, cryptoBytes...)

	// Hash finale
	finalHash := sha256.Sum256(combined)

	if verbose {
		fmt.Printf("⚡ Challenge 1 hash: %x...\n", challenge1.hash[:8])
		fmt.Printf("🎵 Challenge 2 hash: %x...\n", challenge2.hash[:8])
		fmt.Printf("🎲 Crypto/rand: %x...\n", cryptoBytes[:8])
		fmt.Printf("🔐 Final seed: %x...\n", finalHash[:8])
		
		// Statistiche comparative
		avg1, std1 := challenge1.TimingStats()
		avg2, std2 := challenge2.TimingStats()
		fmt.Printf("\n📈 Timing Analysis:\n")
		fmt.Printf("   Challenge 1: %.2f ms avg, %.2f ms variance\n", avg1, std1)
		fmt.Printf("   Challenge 2: %.2f ms avg, %.2f ms variance\n", avg2, std2)
		fmt.Printf("   Difference: %.2f ms (higher = better)\n", abs(avg1-avg2))
	}

	return finalHash[:], nil
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

// Genera password usando l'entropia combinata
func generatePassword(length int, seed []byte, verbose bool) (*memguard.LockedBuffer, error) {
	if length < minLength || length > maxLength {
		return nil, fmt.Errorf("invalid length: must be between %d and %d", minLength, maxLength)
	}

	if verbose {
		fmt.Println("\n🔑 GENERATING PASSWORD")
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Printf("📏 Length: %d characters\n", length)
		fmt.Printf("🎲 Charset: %d possible characters\n", len(charSet))
		fmt.Printf("💪 Entropy: ~%.2f bits\n", float64(length)*6.5)
	}

	// Crea buffer temporaneo per generare la password
	tempPass := make([]byte, length)
	
	// Usa seed come fonte per PRNG deterministic
	reader := sha256.New()
	reader.Write(seed)

	for i := 0; i < length; i++ {
		// Genera nuovo hash ad ogni iterazione per più entropia
		reader.Write(seed)
		reader.Write([]byte{byte(i)})
		hash := reader.Sum(nil)

		// Usa hash per scegliere carattere
		idx := binary.BigEndian.Uint32(hash[:4]) % uint32(len(charSet))
		tempPass[i] = charSet[idx]

		// Re-seed per prossima iterazione
		reader.Reset()
		reader.Write(hash)
	}

	// Crea buffer protetto con memguard dalla password generata
	password := memguard.NewBufferFromBytes(tempPass)
	defer func() {
		if r := recover(); r != nil {
			password.Destroy()
			panic(r)
		}
	}()
	
	// Pulisci buffer temporaneo
	memguard.WipeBytes(tempPass)

	if verbose {
		fmt.Println("✅ Password generated in protected memory")
	}

	return password, nil
}

// Cripta password con Age
func encrypt(password *memguard.LockedBuffer, passphrase, filename string) error {
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return fmt.Errorf("failed to create recipient: %w", err)
	}

	out, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer out.Close()

	w, err := age.Encrypt(out, recipient)
	if err != nil {
		return fmt.Errorf("failed to create encrypted writer: %w", err)
	}

	if _, err := w.Write(password.Bytes()); err != nil {
		return fmt.Errorf("failed to write encrypted data: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("failed to close encrypted writer: %w", err)
	}

	return nil
}

// Decripta password
func decrypt(passphrase, filename string, verbose bool) error {
	if verbose {
		fmt.Println("\n🔓 DECRYPTING PASSWORD")
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	}

	f, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return fmt.Errorf("failed to create identity: %w", err)
	}

	r, err := age.Decrypt(f, identity)
	if err != nil {
		return fmt.Errorf("failed to decrypt (wrong passphrase?): %w", err)
	}

	password, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("failed to read decrypted data: %w", err)
	}
	defer memguard.WipeBytes(password)

	fmt.Printf("\n🔐 Decrypted Password: %s\n", string(password))
	
	if verbose {
		fmt.Printf("📏 Length: %d characters\n", len(password))
	}

	return nil
}

// Richiedi passphrase (nascosta)
func promptPassphrase(prompt string) (string, error) {
	fmt.Print(prompt)
	passBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(passBytes), nil
}

// Cancellazione sicura DoD 5220.22-M (7-pass)
func secureWipe(filename string, verbose bool) error {
	if verbose {
		fmt.Println("\n🔥 SECURE WIPE (DoD 5220.22-M)")
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Printf("📁 Target: %s\n", filename)
		fmt.Printf("🔄 Passes: %d\n\n", wipePassCount)
	}

	// Verifica file esiste
	stat, err := os.Stat(filename)
	if err != nil {
		return fmt.Errorf("file not found: %w", err)
	}

	fileSize := stat.Size()
	if verbose {
		fmt.Printf("📊 File size: %d bytes\n\n", fileSize)
	}

	// Pattern di sovrascrittura DoD 5220.22-M
	patterns := []byte{
		0x00, // Pass 1: tutti zeri
		0xFF, // Pass 2: tutti uno
		0x00, // Pass 3: tutti zeri
		0xFF, // Pass 4: tutti uno
		0x00, // Pass 5: tutti zeri
		0xFF, // Pass 6: tutti uno
		// Pass 7: random (generato dopo)
	}

	// Esegui 7 pass
	for i := 0; i < wipePassCount; i++ {
		if verbose {
			fmt.Printf("🔄 Pass %d/%d: ", i+1, wipePassCount)
		}

		// Apri file in write mode
		f, err := os.OpenFile(filename, os.O_WRONLY, 0)
		if err != nil {
			return fmt.Errorf("failed to open file for wiping: %w", err)
		}

		var pattern []byte
		if i < len(patterns) {
			// Pattern fisso
			pattern = make([]byte, fileSize)
			for j := range pattern {
				pattern[j] = patterns[i]
			}
			if verbose {
				fmt.Printf("Writing 0x%02X pattern\n", patterns[i])
			}
		} else {
			// Random pattern (pass 7)
			pattern = make([]byte, fileSize)
			rand.Read(pattern)
			if verbose {
				fmt.Println("Writing random data")
			}
		}

		// Scrivi pattern
		if _, err := f.Write(pattern); err != nil {
			f.Close()
			return fmt.Errorf("failed to write pattern: %w", err)
		}

		// Sync su disco
		if err := f.Sync(); err != nil {
			f.Close()
			return fmt.Errorf("failed to sync: %w", err)
		}

		f.Close()
	}

	// Rimuovi file
	if err := os.Remove(filename); err != nil {
		return fmt.Errorf("failed to remove file: %w", err)
	}

	if verbose {
		fmt.Println("\n✅ File securely wiped and removed!")
	} else {
		fmt.Printf("✅ %s securely wiped\n", filename)
	}

	return nil
}

func main() {
	memguard.CatchInterrupt()
	defer memguard.Purge()

	// Flags
	length := flag.Int("l", defaultLength, "Password length")
	output := flag.String("o", defaultOutputFile, "Output encrypted file")
	decryptMode := flag.Bool("decrypt", false, "Decrypt mode")
	encfile := flag.String("encfile", defaultOutputFile, "Encrypted file to decrypt")
	wipeMode := flag.Bool("wipe", false, "Secure wipe mode")
	wipefile := flag.String("wipefile", "", "File to securely wipe")
	verbose := flag.Bool("v", false, "Verbose output")
	showVersion := flag.Bool("version", false, "Show version")

	flag.Parse()

	// Version
	if *showVersion {
		fmt.Printf("gensecpass2 v%s\n", version)
		return
	}

	// Wipe mode
	if *wipeMode {
		if *wipefile == "" {
			fmt.Println("❌ Error: -wipefile required for wipe mode")
			os.Exit(1)
		}

		fmt.Printf("⚠️  WARNING: This will PERMANENTLY destroy: %s\n", *wipefile)
		fmt.Print("Are you absolutely sure? (type 'YES' to confirm): ")

		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')

		if strings.TrimSpace(response) != "YES" {
			fmt.Println("❌ Wipe cancelled")
			os.Exit(0)
		}

		if err := secureWipe(*wipefile, *verbose); err != nil {
			fmt.Printf("❌ Wipe failed: %v\n", err)
			os.Exit(1)
		}

		return
	}

	// Decrypt mode
	if *decryptMode {
		pass, err := promptPassphrase("Enter passphrase: ")
		if err != nil {
			fmt.Printf("❌ Error: %v\n", err)
			os.Exit(1)
		}

		if err := decrypt(pass, *encfile, *verbose); err != nil {
			fmt.Printf("❌ Decryption failed: %v\n", err)
			os.Exit(1)
		}

		return
	}

	// Generate mode
	fmt.Printf("╔════════════════════════════════════════════════════╗\n")
	fmt.Printf("║       🔐 GENSECPASS2 v%s                      ║\n", version)
	fmt.Printf("║   Ultra-Secure Password Generator                  ║\n")
	fmt.Printf("║   Dual Keyboard Entropy Collection                 ║\n")
	fmt.Printf("╚════════════════════════════════════════════════════╝\n")

	// Step 1: Challenge 1 - Chaotic typing
	challenge1, err := collectChallenge1Entropy(challenge1Target, *verbose)
	if err != nil {
		fmt.Printf("❌ Challenge 1 failed: %v\n", err)
		os.Exit(1)
	}

	// Step 2: Challenge 2 - Rhythmic typing
	challenge2, err := collectChallenge2Entropy(challenge2Target, *verbose)
	if err != nil {
		fmt.Printf("❌ Challenge 2 failed: %v\n", err)
		os.Exit(1)
	}

	// Step 3: Combine entropy
	seed, err := combineEntropy(challenge1, challenge2, *verbose)
	if err != nil {
		fmt.Printf("❌ Entropy combination failed: %v\n", err)
		os.Exit(1)
	}

	// Step 4: Generate password
	password, err := generatePassword(*length, seed, *verbose)
	if err != nil {
		fmt.Printf("❌ Password generation failed: %v\n", err)
		os.Exit(1)
	}
	defer password.Destroy()

	// Step 5: Save or display
	fmt.Println("\n💾 SAVE OPTIONS")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Print("Save encrypted password to file? (y/N): ")

	reader := bufio.NewReader(os.Stdin)
	response, _ := reader.ReadString('\n')

	if strings.TrimSpace(strings.ToLower(response)) == "y" {
		pass, err := promptPassphrase("Enter passphrase: ")
		if err != nil {
			fmt.Printf("❌ Error: %v\n", err)
			os.Exit(1)
		}

		confirm, err := promptPassphrase("Confirm passphrase: ")
		if err != nil {
			fmt.Printf("❌ Error: %v\n", err)
			os.Exit(1)
		}

		if pass != confirm {
			fmt.Println("❌ Passphrases don't match!")
			os.Exit(1)
		}

		if err := encrypt(password, pass, *output); err != nil {
			fmt.Printf("❌ Encryption failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("\n✅ Password saved to: %s\n", *output)
	} else {
		fmt.Println("\n🔐 Generated Password:", password.String())
		fmt.Println("⚠️  Password displayed only (not saved)")
	}

	fmt.Println("\n🧹 Password destroyed from memory")
	fmt.Println("✅ Session complete!")
}
