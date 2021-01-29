package main

import (
	//"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

var (
	self  string
	magic = []byte{1, 1, 1, 1}
	password = false
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
	path, encrypt := "", false
	i = 1
	for i < len(os.Args) {
		switch os.Args[i] {
		case "-e","--encrypt": encrypt = true
		case "-p","--password": password = true
		case "-h","--help": usage(1, "")
		default:
			if os.Args[i][0] == '-' {
				usage(1, "Error: unknown commandline option: " + os.Args[i])
			}
			if path != "" {
				usage(1, "Error: only 1 file/directory allowed")
			}
			path = os.Args[i]
		}
		i += 1
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
	var pwd []byte
	if password {
		retry := 3
		for retry > 0 {
			fmt.Printf("Set password: ")
			pwd, _ = terminal.ReadPassword(int(syscall.Stdin))
			if len(pwd) == 0 || len([]byte(pwd)) > 30 {
				fmt.Printf("\nAn empty password is not safe")
			} else {
				fmt.Printf("\nConfirm password: ")
				pwd2, _ := terminal.ReadPassword(int(syscall.Stdin))
				fmt.Println("")
				if bytes.Equal(pwd, pwd2) {
					break
				}
				fmt.Printf("Passwords must be the same")
			}
			retry--
			if retry > 0 {
				fmt.Println(", retry")
			} else {
				fmt.Printf("\nStopping here")
				os.Exit(1)
			}
		}
		sha := sha256.Sum256([]byte(pwd))
		key = sha[0:32]
  } else {
		io.ReadFull(rand.Reader, key)
	}
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
	fmt.Printf("Encrypted archive: %s\nDecrypt with '%s'", file, self)
	fmt.Printf(" (https://github.com/pepa65/enc)")
	if !password {
		fmt.Printf(" using decryption key:\n%032x", key)
	}
	fmt.Println()
}

func promptKey() []byte {
	fmt.Println("Enter decryption key:")
	strkey, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		usage(2, fmt.Sprintf("Error %v: cannot read key", err))
	}
	if len(strkey) < 32 {
		key := sha256.Sum256([]byte(strkey))
		return key[0:32]
	} else {
		// Check key
		key, err := hex.DecodeString(strings.TrimSpace(string(strkey)))
		if err != nil {
			usage(2, "Error: invalid key")
		}
		return key
	}
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
		fmt.Printf(self + " - Encrypt/decrypt files/directories\nUsage:  ")
		fmt.Printf(self + "  [-e|--encrypt] [-p|--password] [-h|--help]  ")
		fmt.Printf("<path>\n    -e/--encrypt:   To force encryption of an ")
		fmt.Printf("already encrypted archive.\n                    Only ")
		fmt.Printf("enc-encrypted archives get decrypted (recognizable ")
		fmt.Printf("by\n                    starting with 4 distinctive 'magic' ")
		fmt.Printf("bytes 0x01010101). They\n                    get decrypted ")
		fmt.Printf("into a directory ")
		fmt.Printf("\"enc_<random-suffix>\".\n                    The default ")
		fmt.Printf("operation is encryption, resulting in ")
		fmt.Printf("an\n                    enc-encrypted compressed archive, ")
		fmt.Printf("ending with \".enc\".\n    -p|--password:  Instead of ")
		fmt.Printf("encrypting with a randomly generated 32 ")
		fmt.Printf("byte\n                    hexadecimal password, the user is ")
		fmt.Printf("prompted for a password.\n    -h|--help:      Only show this ")
		fmt.Println("help text, nothing else")
	}
	os.Exit(ret)
}
