package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

var (
	self  string
	magic = []byte{1, 1, 1, 1}
)

func main() {
	self = os.Args[0]
	i := strings.IndexByte(self, '/')
	for i >= 0 {
		self = self[i+1:]
		i = strings.IndexByte(self, '/')
	}
	if len(os.Args) < 2 {
		usage(1, "")
	}
	path, encrypt := os.Args[1], false
	if os.Args[1] == "-e" || os.Args[1] == "--encrypt" {
		if len(os.Args) < 3 {
			usage(1, "Error: path mandatory after -e/--encrypt")
		}
		if len(os.Args) > 3 {
			usage(1, "Error: only path needed after -e/--encrypt")
		}
		path, encrypt = os.Args[2], true
	} else {
		if len(os.Args) > 2 {
			usage(1, "Error: only path needed as argument")
		}
	}

	// If path is a file and has the right magic: try decrypting archive
	f, err := os.Open(path)
	if err != nil {
		usage(1, "Cannot find path: '" + path + "'")
	}
	firstfour := make([]byte, 4)
	n, err := f.Read(firstfour)
	if err != nil { // Not an encrypted file, try encrypting
		encrypt = true
	}
	if !encrypt && n == 4 && bytes.Compare(firstfour, magic) == 0 {
		decryptPath(path)
		return
	}
	encryptPath(path)
}

func decryptPath(path string) {
	// Read encrypted archive, magic bytes already checked
	file, err := ioutil.ReadFile(path)
	if err != nil {
		usage(1, "Error: cannot open " + self + "-archive: " + path)
	}
	nonce := file[4:16]
	key := promptKey()
	AESgcm := wrapKey(key)
	AEScontent, err := AESgcm.Open(nil, nonce, file[16:], nil)
	if err != nil {
		usage(2, "Error: cannot decrypt archive (modified, or key not correct)")
	}

	// Create directory
	err, dir := nil, ""
	for err == nil {
		num := make([]byte, 4)
		io.ReadFull(rand.Reader, num)
		dir = self + "_" + fmt.Sprintf("%x", num)
		_, err = os.Stat(dir)
	}
	err = os.MkdirAll(dir, 0755)
	if err != nil {
		usage(2, "Error: cannot create directory for decryption: " + dir)
	}

	// Decompress
	err = decompress(bytes.NewReader(AEScontent), dir)
	if err != nil {
		usage(2, fmt.Sprintf("%v", err))
	}

	// Notify
	fmt.Println("Archive decrypted into directory '" + dir + "'")
}

func encryptPath(path string) {
	// Randomize nonce
	nonce := make([]byte, 12)
	io.ReadFull(rand.Reader, nonce)

	// Compress file or directory
	var buf bytes.Buffer
	if err := compress(path, &buf)
	err != nil {
		usage(1, fmt.Sprintf("Error: path '%v' not found", path))
	}
	// Encrypt compressed content
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)
	AESgcm := wrapKey(key)
	body := AESgcm.Seal(nil, nonce, buf.Bytes(), nil)

	// Write archive to disk
	file := path + "." + self
	f, err := os.OpenFile(file, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		usage(2, fmt.Sprintf("%v", err))
	}
	defer f.Close()
	// Encrypted archive: magic(0..3) nonce(4..15) body(16..)
	f.Write(magic)
	f.Write(nonce)
	f.Write(body)

	// Notify
	fmt.Printf("Encrypted archive: " + file + "\nDecrypt with '" + self)
	fmt.Println("' (https://github.com/pepa65/enc) using decryption key:")
	fmt.Printf("%032x\n", key)
}

func promptKey() []byte {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Enter decryption key of 64 hexadecimals (32 Bytes, 256 bits):")
	strkey, err := reader.ReadString('\n')
	if err != nil {
		usage(2, fmt.Sprintf("Error %v: cannot read key", err))
	}

	// Check key
	key, err := hex.DecodeString(strings.TrimSpace(strkey))
	if err != nil || len(key) != 32 {
		usage(2, "Error: key is not 64 hexadecimals (32 Bytes, 256 bits)")
	}
	return key
}

func wrapKey(key []byte) cipher.AEAD {
	// Make AES-256 block from 32-Byte key
	cipherAES, err := aes.NewCipher(key)
	if err != nil {
		usage(2, "Error: cannot make AES block")
	}
	// Wrap block in Galois Counter Mode
	AESgcm, err := cipher.NewGCM(cipherAES)
	if err != nil {
		usage(2, "Error: cannot wrap AES block")
	}
	return AESgcm
}

func usage(ret int, mes string) {
	if mes != "" {
		fmt.Printf("%v\n\n", mes)
	}
	if ret == 1 {
		fmt.Printf(self + " - Encrypt/decrypt files/directories\nUsage:  " + self)
		fmt.Printf(" [-e|--encrypt] <path>\n  Encrypt if the -e/--encrypt flag is")
		fmt.Printf(" used or if <path> is not an " + self + "-encrypted\n")
		fmt.Printf("  archive, otherwise decrypt. The encrypted archive gets a .")
		fmt.Printf(self + " extension.\n  An " + self + "-encrypted archive gets")
		fmt.Printf(" decrypted into a directory " + self + "_<random-suffix>.\n")
		fmt.Printf("  All " + self + "-encrypted archives start with 4 ")
		fmt.Println("distinctive 'magic' bytes (all 1).")
	}
	os.Exit(ret)
}
