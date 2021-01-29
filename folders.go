package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func compress(path string, buf io.Writer) error {
	// tar(gzip(buf)
	zw := gzip.NewWriter(buf)
	tw := tar.NewWriter(zw)

	// Is path directory/file
	f, err := os.Stat(path)
	if err != nil {
		return err
	}
	mode := f.Mode()
	if mode.IsRegular() { // Regular file
		header, err := tar.FileInfoHeader(f, path)
		if err != nil {
			return err
		}
		if err := tw.WriteHeader(header)
		err != nil {
			return err
		}
		data, err := os.Open(path)
		if err != nil {
			return err
		}
		if _, err := io.Copy(tw, data)
		err != nil {
			return err
		}
	} else if mode.IsDir() { // Directory
		filepath.Walk(path, func(file string, fi os.FileInfo, err error) error {
			header, err := tar.FileInfoHeader(fi, file)
			if err != nil {
				return err
			}

			// Real name (see https://golang.org/src/archive/tar/common.go?#L626)
			header.Name = filepath.ToSlash(file)
			if err := tw.WriteHeader(header)
			err != nil {
				return err
			}
			// No directory: write
			if !fi.IsDir() {
				data, err := os.Open(file)
				if err != nil {
					return err
				}
				if _, err := io.Copy(tw, data)
				err != nil {
					return err
				}
			}
			return nil
		})
	} else {
		return fmt.Errorf("Error: file type not supported")
	}

	if err := tw.Close()
	err != nil {
		return err
	}
	if err := zw.Close()
	err != nil {
		return err
	}
	return nil
}

// Check path traversal and correct forward slashes
func validRelPath(p string) bool {
	if p == "" || strings.Contains(p, `\`) || strings.HasPrefix(p, "/") ||
			strings.Contains(p, "../") {
		return false
	}
	return true
}

func decompress(src io.Reader, dst string) error {
	// ungzip
	zr, err := gzip.NewReader(src)
	if err != nil {
		return err
	}
	// untar
	tr := tar.NewReader(zr)

	// Uncompress each element
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target := header.Name

		// Validate name against path traversal
		if !validRelPath(header.Name) {
			return fmt.Errorf("Error: tar contained invalid name error %q", target)
		}

		// Add dst + reformat slashes according to system
		target = filepath.Join(dst, header.Name)
		// if no join is needed, replace with ToSlash:
		// target = filepath.ToSlash(header.Name)

		switch header.Typeflag {
		// New directory: create 0755
		case tar.TypeDir:
			if _, err := os.Stat(target)
			err != nil {
				if err := os.MkdirAll(target, 0755)
				err != nil {
					return err
				}
			}
		// New file: create 0755
		case tar.TypeReg:
			fileToWrite, err :=
				os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			// Copy contents
			if _, err := io.Copy(fileToWrite, tr)
			err != nil {
				return err
			}
			// Close explicitly (defer waits for everything to be finished)
			fileToWrite.Close()
		}
	}
	return nil
}
