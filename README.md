# Enc v1.0.0
**Encrypt/decrypt files/directories**
* Repo: https://github.com/pepa65/enc
* After: https://github.com/mimoo/eureka
  - Implementation is not compatible at all!

## Usage
```
enc v1.0.0 - Encrypt/decrypt files/directories
Usage: enc [-e|--encrypt] [-f|--force] [-h|--help] <path>
    -e|--encrypt:  Force encryption of an already encrypted archive.
    -f|--force:    Replace an existing .enc archive.
    -h|--help:     Show this help text.

Encryption uses a password with Argon2id and a random
per-archive salt, followed by AES-256-GCM encryption.
```

### Examples
Making a compressed encrypted archive with a 32 byte hexadecimal password out
of `file`, resulting in `file.enc`:  `enc file`

The same, overwrite existing `file.enc`: `enc --force file`

Making a compressed encrypted archive with a user-supplied password out of the
contents of directory `dir`, resulting in `dir.enc`:  `enc -p dir`

Decrypting the contents of enc-encrypted archive `dir.enc` into directory
`enc_????????`: `enc dir.enc`

Encrypting enc-encrypted archive `file.enc` again: `enc --encrypt file.enc`

## Install
* **gobinaries.com**: `wget -qO- gobinaries.com/pepa65/enc |sh`
* **Go get** If [Golang](https://golang.org/) is installed properly:
  `go get github.com/pepa65/enc`
* **Go install** If [Golang](https://golang.org/) is installed properly:
  `go install github.com/pepa65/enc@latest`
* **Go build/install**
  - `git clone https://github.com/pepa65/enc; cd enc; go install`
  - Smaller binary: `go build -ldflags="-s -w"; upx enc`
* **Build for other architectures**
```
GOOS=linux GOARCH=arm go build -ldflags="-s -w" -o enc_pi
GOOS=freebsd GOARCH=amd64 go build -ldflags="-s -w" -o enc_freebsd
GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o enc_osx
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o enc.exe
```
* **Download binaries**
  - [Linux (amd64)](https://github.com/pepa65/enc/raw/master/enc)
  - [Linux (arm)](https://github.com/pepa65/enc/raw/master/enc_pi)
  - [FreeBSD](https://github.com/pepa65/enc/raw/master/enc_freebsd)
  - [OSX](https://github.com/pepa65/enc/raw/master/enc_osx)
  - [Windows (x86_64)](https://github.com/pepa65/enc/raw/master/enc.exe)
* **Add magic for the `file` command**
  - `echo '0 long 0x656e6331 enc v1 encrypted data, gitlab.com/pepa65/enc' |
    sudo tee -a /etc/magic`
