package limitio

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

var ErrSizeExceeded = errors.New("size exceeds limit")

// IsSizeExceeded reports whether err indicates strict size-limit overflow.
func IsSizeExceeded(err error) bool {
	return errors.Is(err, ErrSizeExceeded)
}

// CopyWithStrictLimit copies from src to dst and fails closed when src
// contains bytes beyond maxBytes, without writing overflow bytes to dst.
func CopyWithStrictLimit(dst io.Writer, src io.Reader, maxBytes int64) (int64, error) {
	if maxBytes < 0 {
		return 0, ErrSizeExceeded
	}
	if maxBytes == 0 {
		var probe [1]byte
		n, err := src.Read(probe[:])
		if n > 0 {
			return 0, ErrSizeExceeded
		}
		if err != nil && err != io.EOF {
			return 0, err
		}
		return 0, nil
	}

	buf := make([]byte, 32*1024)
	var written int64
	for written < maxBytes {
		remaining := maxBytes - written
		chunkSize := int64(len(buf))
		if remaining < chunkSize {
			chunkSize = remaining
		}
		n, err := src.Read(buf[:chunkSize])
		if n > 0 {
			wn, werr := dst.Write(buf[:n])
			written += int64(wn)
			if werr != nil {
				return written, werr
			}
			if wn != n {
				return written, io.ErrShortWrite
			}
		}
		if err == io.EOF {
			return written, nil
		}
		if err != nil {
			return written, err
		}
	}

	var probe [1]byte
	n, err := src.Read(probe[:])
	if n > 0 {
		return written, ErrSizeExceeded
	}
	if err != nil && err != io.EOF {
		return written, err
	}
	return written, nil
}

// FileInfoStatter is implemented by opened files that can report current file
// metadata for time-of-check/time-of-use validation.
type FileInfoStatter interface {
	Stat() (os.FileInfo, error)
}

// StableOpenCheck verifies that an opened file still matches the previously
// observed file metadata.
type StableOpenCheck func(previous os.FileInfo, opened FileInfoStatter, path string) error

// CopyFileWithModeChecked copies src to a newly-created dst, preserving the
// strict byte limit and removing partial destination files on copy failure.
func CopyFileWithModeChecked(
	src string,
	dst string,
	mode os.FileMode,
	maxBytes int64,
	expectedInfo os.FileInfo,
	checkStable StableOpenCheck,
) (int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return 0, fmt.Errorf("failed to open source file: %w", err)
	}
	defer in.Close()
	if expectedInfo != nil && checkStable != nil {
		if err := checkStable(expectedInfo, in, src); err != nil {
			return 0, err
		}
	}

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return 0, fmt.Errorf("failed to create destination file: %w", err)
	}
	defer func() {
		_ = out.Close()
	}()

	written, err := CopyWithStrictLimit(out, in, maxBytes)
	if err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return 0, err
	}
	return written, nil
}

// HashSHA256FileWithLimitChecked hashes path with a strict byte limit and an
// optional opened-file stability check.
func HashSHA256FileWithLimitChecked(
	path string,
	maxBytes int64,
	expectedInfo os.FileInfo,
	checkStable StableOpenCheck,
) (sum string, size int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("failed to open file for hashing: %w", err)
	}
	defer f.Close()
	if expectedInfo != nil && checkStable != nil {
		if err := checkStable(expectedInfo, f, path); err != nil {
			return "", 0, err
		}
	}

	hasher := sha256.New()
	var n int64
	if maxBytes >= 0 {
		n, err = CopyWithStrictLimit(hasher, f, maxBytes)
	} else {
		n, err = io.Copy(hasher, f)
	}
	if err != nil {
		if errors.Is(err, ErrSizeExceeded) {
			return "", 0, err
		}
		return "", 0, fmt.Errorf("failed to hash file: %w", err)
	}
	return hex.EncodeToString(hasher.Sum(nil)), n, nil
}
