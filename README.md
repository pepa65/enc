# Enc
**Encrypt/decrypt files/directories**
* Repo: https://github.com/pepa65/enc
* After: https://github.com/mimoo/eureka
* Contact: pepa65 <pepa65@passchier.net>

## Install
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

## Usage
```
enc [-e|--encrypt] <path>
    If the -e/--encrypt flag is used or if <path> is not an enc-encrypted
    file, then Encrypt. The encrypted archive gets a .enc extension.
    If <path> is an enc-encrypted file, then Decrypt into directory enc_*.
    enc-encrypted files start with 4 distinctive 'magic' bytes (all 1).
```
