package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/crypto/argon2"
	terminal "golang.org/x/term"
)

var (
	self    string
	version = "1.0.0"
	magic   = []byte{'e', 'n', 'c', '1'}
)

const (
	saltSize  = 16
	nonceSize = 12
	keySize   = 32

	argonTime    = 9
	argonMemory  = 256 * 1024 // 256 MiB, in KiB
	argonThreads = 1
)

func main() {
	self = filepath.Base(os.Args[0])

	if len(os.Args) < 2 {
		usage(1, "")
	}

	path, encrypt, forced := "", false, false

	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-e", "--encrypt":
			encrypt = true
		case "-f", "--force":
			forced = true
		case "-h", "--help":
			usage(1, "")
		default:
			if strings.HasPrefix(os.Args[i], "-") {
				usage(1, "Error: unknown commandline option: "+os.Args[i])
			}
			if path != "" {
				usage(1, "Error: only 1 file/directory allowed")
			}
			path = os.Args[i]
		}
	}

	if path == "" {
		usage(1, "Error: no input path given")
	}

	// Detect an enc1 archive. Everything else is treated as input
	// to encryption unless encryption was explicitly selected.
	f, err := os.Open(path)
	if err != nil {
		usage(1, "Cannot find path: '"+path+"'")
	}

	var firstFour [4]byte
	n, readErr := io.ReadFull(f, firstFour[:])
	_ = f.Close()

	if readErr == nil && n == len(magic) && bytes.Equal(firstFour[:], magic) && !encrypt {
		decryptPath(path)
		return
	}

	encryptPath(path, forced)
}

func derivePassword(password []byte, salt []byte) []byte {
	return argon2.IDKey(
		password,
		salt,
		argonTime,
		argonMemory,
		argonThreads,
		keySize,
	)
}

func decryptPath(path string) {
	file, err := os.ReadFile(path)
	if err != nil {
		usage(2, "Error: cannot open encrypted archive: "+path)
	}

	minSize := len(magic) + saltSize + nonceSize + 16
	if len(file) < minSize {
		usage(2, "Error: encrypted archive is too short")
	}

	if !bytes.Equal(file[:len(magic)], magic) {
		usage(2, "Error: unsupported archive format")
	}

	saltStart := len(magic)
	saltEnd := saltStart + saltSize

	nonceStart := saltEnd
	nonceEnd := nonceStart + nonceSize

	salt := file[saltStart:saltEnd]
	nonce := file[nonceStart:nonceEnd]
	body := file[nonceEnd:]

	pwd := promptPassword("Password: ")
	key := derivePassword(pwd, salt)

	// Best-effort clearing of sensitive material after key derivation.
	defer func() {
		for i := range pwd {
			pwd[i] = 0
		}
		for i := range key {
			key[i] = 0
		}
	}()

	AESgcm := wrapKey(key)

	AEScontent, err := AESgcm.Open(nil, nonce, body, nil)
	if err != nil {
		usage(2, "Error: cannot decrypt archive (modified, or password not correct)")
	}

	dir, err := createDecryptionDir()
	if err != nil {
		usage(2, fmt.Sprintf("Error: cannot create directory for decryption: %v", err))
	}

	if err := decompress(bytes.NewReader(AEScontent), dir); err != nil {
		_ = os.RemoveAll(dir)
		usage(2, fmt.Sprintf("Error: cannot extract archive: %v", err))
	}

	fmt.Println("Archive decrypted into directory '" + dir + "'")
}

func encryptPath(path string, forced bool) {
	file := path + "." + self

	if _, err := os.Stat(file); err == nil && !forced {
		fmt.Println("Error: destination file '" + file + "' already exists")
		os.Exit(1)
	} else if err != nil && !os.IsNotExist(err) {
		usage(2, fmt.Sprintf("Error checking destination: %v", err))
	}

	// Compress the input before encryption.
	var buf bytes.Buffer
	if err := compress(path, &buf); err != nil {
		usage(1, fmt.Sprintf("Error: cannot compress path '%v': %v", path, err))
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		usage(2, fmt.Sprintf("Error: cannot generate nonce: %v", err))
	}

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		usage(2, fmt.Sprintf("Error: cannot generate salt: %v", err))
	}

	pwd := promptPassword("Set password: ")

	fmt.Printf("Confirm password: ")
	pwd2, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		for i := range pwd {
			pwd[i] = 0
		}
		usage(2, fmt.Sprintf("Error: cannot read password confirmation: %v", err))
	}
	fmt.Println()

	if !bytes.Equal(pwd, pwd2) {
		for i := range pwd {
			pwd[i] = 0
		}
		for i := range pwd2 {
			pwd2[i] = 0
		}
		usage(1, "Error: passwords do not match")
	}

	key := derivePassword(pwd, salt)

	for i := range pwd {
		pwd[i] = 0
	}
	for i := range pwd2 {
		pwd2[i] = 0
	}

	AESgcm := wrapKey(key)
	body := AESgcm.Seal(nil, nonce, buf.Bytes(), nil)

	for i := range key {
		key[i] = 0
	}

	// Archive:
	// magic(4) | salt(16) | nonce(12) | ciphertext
	dir := filepath.Dir(file)
	base := filepath.Base(file)

	tmp, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		usage(2, fmt.Sprintf("Error: cannot create temporary archive: %v", err))
	}
	tmpName := tmp.Name()

	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}

	defer cleanup()

	if _, err := tmp.Write(magic); err != nil {
		usage(2, fmt.Sprintf("Error writing archive: %v", err))
	}
	if _, err := tmp.Write(salt); err != nil {
		usage(2, fmt.Sprintf("Error writing archive: %v", err))
	}
	if _, err := tmp.Write(nonce); err != nil {
		usage(2, fmt.Sprintf("Error writing archive: %v", err))
	}
	if _, err := tmp.Write(body); err != nil {
		usage(2, fmt.Sprintf("Error writing archive: %v", err))
	}

	if err := tmp.Sync(); err != nil {
		usage(2, fmt.Sprintf("Error syncing archive: %v", err))
	}

	if err := tmp.Close(); err != nil {
		usage(2, fmt.Sprintf("Error closing archive: %v", err))
	}

	if err := os.Rename(tmpName, file); err != nil {
		usage(2, fmt.Sprintf("Error replacing destination: %v", err))
	}

	fmt.Printf("Encrypted archive: %s\n", file)
	fmt.Printf("Decrypt with '%s'\n", self)
}

func promptPassword(promptText string) []byte {
	fmt.Print(promptText)

	password, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		usage(2, fmt.Sprintf("Error: cannot read password: %v", err))
	}

	fmt.Println()

	if len(password) == 0 {
		usage(1, "Error: password is empty")
	}

	return password
}

func wrapKey(key []byte) cipher.AEAD {
	cipherAES, err := aes.NewCipher(key)
	if err != nil {
		usage(2, "Error: cannot make AES block")
	}

	AESgcm, err := cipher.NewGCM(cipherAES)
	if err != nil {
		usage(2, "Error: cannot wrap AES block")
	}

	return AESgcm
}

func createDecryptionDir() (string, error) {
	for {
		var suffix [4]byte
		if _, err := io.ReadFull(rand.Reader, suffix[:]); err != nil {
			return "", err
		}

		dir := fmt.Sprintf("%s_%x", self, suffix)

		if _, err := os.Stat(dir); err == nil {
			continue
		} else if err != nil && !os.IsNotExist(err) {
			return "", err
		}

		if err := os.Mkdir(dir, 0700); err != nil {
			if os.IsExist(err) {
				continue
			}
			return "", err
		}

		return dir, nil
	}
}

func usage(ret int, mes string) {
	if mes != "" {
		fmt.Printf("%v\n\n", mes)
	}

	if ret == 1 {
		fmt.Printf(
			"%s v%s - Encrypt/decrypt files/directories\n"+
				"Usage: %s [-e|--encrypt] [-f|--force] [-h|--help] <path>\n"+
				"    -e|--encrypt:  Force encryption of an already encrypted archive.\n"+
				"    -f|--force:    Replace an existing .%s archive.\n"+
				"    -h|--help:     Show this help text.\n"+
				"\n"+
				"Encryption uses a password with Argon2id and a random\n"+
				"per-archive salt, followed by AES-256-GCM encryption.\n",
			self, version, self, self,
		)
	}

	os.Exit(ret)
}
