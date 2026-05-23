package limitio

import (
	"errors"
	"io"
)

var ErrSizeExceeded = errors.New("size exceeds limit")

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
