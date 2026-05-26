package materialize

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/watany-dev/gokui/internal/limitio"
)

const (
	defaultMaxFiles                  = 1000
	defaultMaxTotalBytes             = 50 * 1024 * 1024
	defaultMaxFileBytes              = 10 * 1024 * 1024
	ruleArchivePathEscape            = "ARCHIVE_PATH_ESCAPE"
	ruleArchivePathInvalidUTF8       = "ARCHIVE_PATH_INVALID_UTF8"
	ruleSymlinkInArchive             = "SYMLINK_IN_ARCHIVE"
	ruleArchiveSourceSymlinkDetected = "ARCHIVE_SOURCE_SYMLINK_DETECTED"
	ruleArchiveSourceSpecialFile     = "ARCHIVE_SOURCE_SPECIAL_FILE"
	ruleArchiveSourceChanged         = "ARCHIVE_SOURCE_CHANGED_DURING_OPEN"
)

// Limits controls archive extraction limits.
type Limits struct {
	MaxFiles      int
	MaxTotalBytes int64
	MaxFileBytes  int64
}

type fileInfoStatter interface {
	Stat() (os.FileInfo, error)
}

// ExtractArchive safely expands src archive into destDir.
// kind must be "zip" or "tar".
func ExtractArchive(src, kind, destDir string, limits Limits) error {
	if err := ensureEmptyDir(destDir); err != nil {
		return err
	}

	effective := normalizeLimits(limits)
	switch kind {
	case "zip":
		return extractZip(src, destDir, effective)
	case "tar":
		return extractTar(src, destDir, effective)
	default:
		return fmt.Errorf("unsupported archive kind: %s", kind)
	}
}

// DetectSkillRoot returns a skill root under extractedDir.
// It accepts either:
// - SKILL.md directly under extractedDir
// - exactly one top-level directory that contains SKILL.md
func DetectSkillRoot(extractedDir string) (string, error) {
	rootSkill := filepath.Join(extractedDir, "SKILL.md")
	if info, err := os.Stat(rootSkill); err == nil && !info.IsDir() {
		return extractedDir, nil
	}

	entries, err := os.ReadDir(extractedDir)
	if err != nil {
		return "", fmt.Errorf("failed to read extracted archive: %w", err)
	}
	if len(entries) != 1 || !entries[0].IsDir() {
		return "", fmt.Errorf("archive must contain SKILL.md at root or in a single top-level directory")
	}

	candidate := filepath.Join(extractedDir, entries[0].Name())
	candidateSkill := filepath.Join(candidate, "SKILL.md")
	if info, err := os.Stat(candidateSkill); err == nil && !info.IsDir() {
		return candidate, nil
	}
	return "", fmt.Errorf("archive must contain SKILL.md at root or in a single top-level directory")
}

func normalizeLimits(in Limits) Limits {
	out := in
	if out.MaxFiles <= 0 {
		out.MaxFiles = defaultMaxFiles
	}
	if out.MaxTotalBytes <= 0 {
		out.MaxTotalBytes = defaultMaxTotalBytes
	}
	if out.MaxFileBytes <= 0 {
		out.MaxFileBytes = defaultMaxFileBytes
	}
	return out
}

func ensureEmptyDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("destination directory does not exist: %s", dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("destination must be a directory: %s", dir)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("failed to read destination directory: %w", err)
	}
	if len(entries) > 0 {
		return fmt.Errorf("destination directory must be empty: %s", dir)
	}
	return nil
}

func extractZip(src, dest string, limits Limits) error {
	file, info, err := openArchiveSource(src, "zip")
	if err != nil {
		return err
	}
	defer file.Close()

	reader, err := zip.NewReader(file, info.Size())
	if err != nil {
		return fmt.Errorf("failed to open zip archive: %w", err)
	}

	var files int
	var totalBytes int64
	for _, file := range reader.File {
		path, err := safeJoin(dest, file.Name)
		if err != nil {
			return err
		}

		mode := file.Mode()
		if mode&os.ModeSymlink != 0 {
			return fmt.Errorf("%s: archive contains symlink entry: %s", ruleSymlinkInArchive, file.Name)
		}

		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(path, 0o755); err != nil {
				return fmt.Errorf("failed to create archive directory: %w", err)
			}
			continue
		}

		files++
		if files > limits.MaxFiles {
			return fmt.Errorf("archive exceeds max files limit: %d", limits.MaxFiles)
		}

		declaredSize := int64(file.UncompressedSize64)
		if declaredSize > limits.MaxFileBytes {
			return fmt.Errorf("archive file exceeds max file bytes: %s", file.Name)
		}
		remainingTotal := limits.MaxTotalBytes - totalBytes
		if remainingTotal <= 0 {
			return fmt.Errorf("archive exceeds max total bytes: %d", limits.MaxTotalBytes)
		}
		if declaredSize > remainingTotal {
			return fmt.Errorf("archive exceeds max total bytes: %d", limits.MaxTotalBytes)
		}
		maxWrite := limits.MaxFileBytes
		if remainingTotal < maxWrite {
			maxWrite = remainingTotal
		}

		written, err := writeZipFile(file, path, maxWrite)
		if err != nil {
			return err
		}
		totalBytes += written
		if totalBytes > limits.MaxTotalBytes {
			return fmt.Errorf("archive exceeds max total bytes: %d", limits.MaxTotalBytes)
		}
	}

	return nil
}

func writeZipFile(file *zip.File, outPath string, maxBytes int64) (int64, error) {
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return 0, fmt.Errorf("failed to create parent directory: %w", err)
	}

	rc, err := file.Open()
	if err != nil {
		return 0, fmt.Errorf("failed to open archive file %s: %w", file.Name, err)
	}
	defer rc.Close()

	out, err := os.OpenFile(outPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return 0, fmt.Errorf("failed to create output file %s: %w", outPath, err)
	}

	written, err := copyWithStrictLimit(out, rc, maxBytes)
	if err != nil {
		_ = out.Close()
		if limitio.IsSizeExceeded(err) {
			_ = os.Remove(outPath)
			return 0, fmt.Errorf("archive file exceeds max file bytes during extraction: %s", file.Name)
		}
		_ = os.Remove(outPath)
		return 0, fmt.Errorf("failed to extract file %s: %w", file.Name, err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(outPath)
		return 0, fmt.Errorf("failed to close extracted file %s: %w", file.Name, err)
	}
	return written, nil
}

func extractTar(src, dest string, limits Limits) error {
	file, _, err := openArchiveSource(src, "tar")
	if err != nil {
		return err
	}
	defer file.Close()

	var reader io.Reader = file
	if strings.HasSuffix(strings.ToLower(src), ".tgz") || strings.HasSuffix(strings.ToLower(src), ".tar.gz") {
		gz, err := gzip.NewReader(file)
		if err != nil {
			return fmt.Errorf("failed to open gzip stream: %w", err)
		}
		defer gz.Close()
		reader = gz
	}

	tarReader := tar.NewReader(reader)
	var files int
	var totalBytes int64
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed reading tar archive: %w", err)
		}

		path, err := safeJoin(dest, header.Name)
		if err != nil {
			return err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, 0o755); err != nil {
				return fmt.Errorf("failed to create archive directory: %w", err)
			}
			continue
		case tar.TypeReg:
			// continue below
		case tar.TypeSymlink:
			return fmt.Errorf("%s: archive contains symlink entry: %s", ruleSymlinkInArchive, header.Name)
		case tar.TypeLink:
			return fmt.Errorf("%s: archive contains hardlink entry: %s", ruleSymlinkInArchive, header.Name)
		default:
			return fmt.Errorf("archive contains unsupported special entry: %s", header.Name)
		}

		files++
		if files > limits.MaxFiles {
			return fmt.Errorf("archive exceeds max files limit: %d", limits.MaxFiles)
		}

		if header.Size < 0 {
			return fmt.Errorf("archive file has negative size: %s", header.Name)
		}
		if header.Size > limits.MaxFileBytes {
			return fmt.Errorf("archive file exceeds max file bytes: %s", header.Name)
		}
		totalBytes += header.Size
		if totalBytes > limits.MaxTotalBytes {
			return fmt.Errorf("archive exceeds max total bytes: %d", limits.MaxTotalBytes)
		}

		if _, err := writeTarFile(header, tarReader, path, limits.MaxFileBytes); err != nil {
			return err
		}
	}

	return nil
}

func openArchiveSource(src string, kind string) (*os.File, os.FileInfo, error) {
	if err := rejectArchiveSourceSymlinkPath(src); err != nil {
		return nil, nil, err
	}

	info, err := os.Lstat(src)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open %s archive: %w", kind, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("%s: archive source must not be a symlink: %s", ruleArchiveSourceSymlinkDetected, src)
	}
	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s: archive source must be a regular file: %s", ruleArchiveSourceSpecialFile, src)
	}

	file, err := os.Open(src)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open %s archive: %w", kind, err)
	}
	if err := ensureArchiveSourceStableFromOpen(info, file, src); err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	return file, info, nil
}

func rejectArchiveSourceSymlinkPath(src string) error {
	for _, candidate := range symlinkCheckCandidates(src) {
		info, err := os.Lstat(candidate)
		if err != nil {
			if os.IsNotExist(err) || errors.Is(err, syscall.ENOTDIR) {
				return nil
			}
			return fmt.Errorf("failed to evaluate archive source path: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if isRootLevelPathComponent(candidate) {
				continue
			}
			return fmt.Errorf("%s: archive source must not be a symlink: %s", ruleArchiveSourceSymlinkDetected, src)
		}
	}
	return nil
}

func symlinkCheckCandidates(path string) []string {
	cleanPath := filepath.Clean(path)
	candidates := []string{cleanPath}

	for current := cleanPath; ; {
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		candidates = append(candidates, parent)
		current = parent
	}

	for i, j := 0, len(candidates)-1; i < j; i, j = i+1, j-1 {
		candidates[i], candidates[j] = candidates[j], candidates[i]
	}

	return candidates
}

func isRootLevelPathComponent(path string) bool {
	cleanPath := filepath.Clean(path)
	if !filepath.IsAbs(cleanPath) {
		return false
	}
	parent := filepath.Dir(cleanPath)
	if parent == cleanPath {
		return false
	}
	return filepath.Dir(parent) == parent
}

func ensureArchiveSourceStableFromOpen(previous os.FileInfo, opened fileInfoStatter, src string) error {
	current, err := opened.Stat()
	if err != nil {
		return fmt.Errorf("failed to open archive source: %s", src)
	}
	if os.SameFile(previous, current) {
		return nil
	}
	return fmt.Errorf("%s: archive source changed during open: %s", ruleArchiveSourceChanged, src)
}

func writeTarFile(header *tar.Header, tarReader *tar.Reader, outPath string, maxBytes int64) (int64, error) {
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return 0, fmt.Errorf("failed to create parent directory: %w", err)
	}

	out, err := os.OpenFile(outPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return 0, fmt.Errorf("failed to create output file %s: %w", outPath, err)
	}

	written, err := copyWithStrictLimit(out, tarReader, maxBytes)
	if err != nil {
		_ = out.Close()
		if limitio.IsSizeExceeded(err) {
			_ = os.Remove(outPath)
			return 0, fmt.Errorf("archive file exceeds max file bytes during extraction: %s", header.Name)
		}
		_ = os.Remove(outPath)
		return 0, fmt.Errorf("failed to extract file %s: %w", header.Name, err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(outPath)
		return 0, fmt.Errorf("failed to close extracted file %s: %w", header.Name, err)
	}
	return written, nil
}

func copyWithStrictLimit(dst io.Writer, src io.Reader, maxBytes int64) (int64, error) {
	return limitio.CopyWithStrictLimit(dst, src, maxBytes)
}

func safeJoin(root, name string) (string, error) {
	if !utf8.ValidString(name) {
		return "", fmt.Errorf("%s: archive path must be valid UTF-8: %q", ruleArchivePathInvalidUTF8, name)
	}
	normalized := strings.ReplaceAll(name, "\\", "/")
	if strings.HasPrefix(normalized, "/") || filepath.IsAbs(name) || hasWindowsDrivePrefix(normalized) {
		return "", fmt.Errorf("%s: archive contains absolute path: %s", ruleArchivePathEscape, name)
	}
	cleanName := path.Clean(normalized)
	if cleanName == "." {
		return "", fmt.Errorf("archive contains invalid path: %s", name)
	}
	if hasWindowsDrivePrefix(cleanName) {
		return "", fmt.Errorf("%s: archive contains absolute path: %s", ruleArchivePathEscape, name)
	}
	if cleanName == ".." || strings.HasPrefix(cleanName, "../") {
		return "", fmt.Errorf("%s: archive path escapes destination: %s", ruleArchivePathEscape, name)
	}

	joined := filepath.Join(root, filepath.FromSlash(cleanName))
	rel, err := filepath.Rel(root, joined)
	if err != nil {
		return "", fmt.Errorf("failed to validate archive path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%s: archive path escapes destination: %s", ruleArchivePathEscape, name)
	}
	return joined, nil
}

func hasWindowsDrivePrefix(path string) bool {
	if len(path) < 3 {
		return false
	}
	drive := path[0]
	if (drive < 'a' || drive > 'z') && (drive < 'A' || drive > 'Z') {
		return false
	}
	return path[1] == ':' && path[2] == '/'
}
