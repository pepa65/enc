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
	zw := gzip.NewWriter(buf)
	tw := tar.NewWriter(zw)

	info, err := os.Stat(path)
	if err != nil {
		_ = tw.Close()
		_ = zw.Close()
		return err
	}

	if info.Mode().IsRegular() {
		header, err := tar.FileInfoHeader(info, path)
		if err != nil {
			_ = tw.Close()
			_ = zw.Close()
			return err
		}

		header.Name = filepath.ToSlash(path)

		if err := tw.WriteHeader(header); err != nil {
			_ = tw.Close()
			_ = zw.Close()
			return err
		}

		data, err := os.Open(path)
		if err != nil {
			_ = tw.Close()
			_ = zw.Close()
			return err
		}

		_, copyErr := io.Copy(tw, data)
		closeErr := data.Close()

		if copyErr != nil {
			_ = tw.Close()
			_ = zw.Close()
			return copyErr
		}
		if closeErr != nil {
			_ = tw.Close()
			_ = zw.Close()
			return closeErr
		}
	} else if info.IsDir() {
		err := filepath.Walk(path, func(file string, fi os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// Do not archive special filesystem objects.
			if !fi.Mode().IsRegular() && !fi.IsDir() {
				return fmt.Errorf("unsupported file type: %q", file)
			}

			header, err := tar.FileInfoHeader(fi, file)
			if err != nil {
				return err
			}

			header.Name = filepath.ToSlash(file)

			if err := tw.WriteHeader(header); err != nil {
				return err
			}

			if fi.IsDir() {
				return nil
			}

			data, err := os.Open(file)
			if err != nil {
				return err
			}

			_, copyErr := io.Copy(tw, data)
			closeErr := data.Close()

			if copyErr != nil {
				return copyErr
			}
			return closeErr
		})
		if err != nil {
			_ = tw.Close()
			_ = zw.Close()
			return err
		}
	} else {
		_ = tw.Close()
		_ = zw.Close()
		return fmt.Errorf("error: file type not supported")
	}

	if err := tw.Close(); err != nil {
		_ = zw.Close()
		return err
	}

	if err := zw.Close(); err != nil {
		return err
	}

	return nil

}

// validRelPath accepts only ordinary relative paths using '/' separators.
// In particular, it rejects absolute paths and any path containing a ".."
// component. Backslashes are rejected so that Windows-style paths cannot
// acquire a different meaning on another platform.
func validRelPath(p string) bool {
	if p == "" {
		return false
	}

	if strings.ContainsRune(p, '\\') {
		return false
	}

	if strings.HasPrefix(p, "/") {
		return false
	}

	clean := filepath.ToSlash(filepath.Clean(p))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return false
	}

	for _, component := range strings.Split(clean, "/") {
		if component == ".." || component == "" {
			return false
		}
	}

	return true

}

func decompress(src io.Reader, dst string) error {
	zr, err := gzip.NewReader(src)
	if err != nil {
		return err
	}
	defer zr.Close()

	tr := tar.NewReader(zr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		if !validRelPath(header.Name) {
			return fmt.Errorf("tar contained invalid path %q", header.Name)
		}

		target := filepath.Join(dst, filepath.FromSlash(header.Name))

		// Do not permit the resulting path to escape dst.
		relative, err := filepath.Rel(dst, target)
		if err != nil || relative == ".." ||
			strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("tar path escapes destination: %q", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}

		case tar.TypeReg, tar.TypeRegA:
			parent := filepath.Dir(target)
			if err := os.MkdirAll(parent, 0755); err != nil {
				return err
			}

			fileToWrite, err := os.OpenFile(
				target,
				os.O_WRONLY|os.O_CREATE|os.O_EXCL,
				os.FileMode(header.Mode)&0777,
			)
			if err != nil {
				return err
			}

			_, copyErr := io.Copy(fileToWrite, tr)
			closeErr := fileToWrite.Close()

			if copyErr != nil {
				_ = os.Remove(target)
				return copyErr
			}
			if closeErr != nil {
				_ = os.Remove(target)
				return closeErr
			}

		default:
			// Do not extract symlinks, hard links, devices, FIFOs, or
			// other special tar entries.
			return fmt.Errorf(
				"unsupported tar entry type %d for %q",
				header.Typeflag,
				header.Name,
			)
		}
	}

}
