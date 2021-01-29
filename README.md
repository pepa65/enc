# Enc
**Encrypt/decrypt files/directories**
* Repo: https://github.com/pepa65/enc
* Contact: pepa65 <pepa65@passchier.net>
* After: https://github.com/mimoo/eureka
  - Implementation is not compatible, because `enc` uses a random nonce as
opposed to a fixed one, and `enc` embeds 4 magic bytes at the start of each
encrypted file.

## Usage
```
enc - Encrypt/decrypt files/directories

Usage:  enc [-e|--encrypt] [-p|--password] [-h|--help] <path>

    -e/--encrypt:   To force encryption of an already encrypted archive.
                    Only enc-encrypted archives get decrypted (recognizable by
                    starting with 4 distinctive 'magic' bytes 0x01010101). They
                    get decrypted into a directory "enc_<random-suffix>".
                    The default operation is encryption, resulting in an
                    enc-encrypted compressed archive, ending with ".enc".
    -p|--password:  Instead of encrypting with a randomly generated 32 byte
                    hexadecimal password, the user is prompted for a password.
    -h|--help:      Only show this help text, nothing else
```

### Examples
Making a compressed encrypted archive with a 32 byte hexadecimal password out
of `file`, resulting in `file.enc`:  `enc file`

Making a compressed encrypted archive with a user-supplied password out of the
contents of directory `dir`, resulting in `dir.enc`:  `enc -p dir`

Decrypting the contents of enc-encrypted archive `dir.enc` into directory
`enc_????????`: `enc dir.enc`

Encrypting enc-encrypted archive `file.enc` again: `enc --encrypt file.enc`

## Install
* **gobinaries.com**: `wget -qO- gobinaries.com/pepa65/enc |sh`
* **Go get** If [Golang](https://golang.org/) is installed properly:
`go get github.com/pepa65/enc`
* **Go build/install**
  - `git clone https://github.com/pepa65/enc; cd enc; go install`
  - Smaller binary: `go build -ldflags="-s -w"; upx --brute enc`
* **Build for other architectures**
  - `GOOS=linux GOARCH=arm go build -ldflags="-s -w" -o enc_pi`
  - `GOOS=freebsd GOARCH=amd64 go build -ldflags="-s -w" -o enc_bsd`
  - `GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o enc_osx`
  - `GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o enc.exe`
* **Download binaries**
  - [Linux (amd64)](https://github.com/pepa65/enc/raw/master/enc)
  - [Linux (arm)](https://github.com/pepa65/enc/raw/master/enc_pi)
  - [FreeBSD](https://github.com/pepa65/enc/raw/master/enc_bsd)
  - [OSX](https://github.com/pepa65/enc/raw/master/enc_osx)
  - [Windows (x86_64)](https://github.com/pepa65/enc/raw/master/enc.exe)
* **Add magic for the `file` command**
  - `echo '0 long 0x01010101 enc encrypted data, gitlab.com/pepa65/enc' |
    sudo tee -a /etc/magic`
