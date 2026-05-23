package materialize

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const (
	defaultMaxFiles       = 1000
	defaultMaxTotalBytes  = 50 * 1024 * 1024
	defaultMaxFileBytes   = 10 * 1024 * 1024
	ruleArchivePathEscape = "ARCHIVE_PATH_ESCAPE"
	ruleSymlinkInArchive  = "SYMLINK_IN_ARCHIVE"
)

// Limits controls archive extraction limits.
type Limits struct {
	MaxFiles      int
	MaxTotalBytes int64
	MaxFileBytes  int64
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

	var dirs []os.DirEntry
	for _, entry := range entries {
		if entry.IsDir() {
			dirs = append(dirs, entry)
		}
	}

	if len(dirs) != 1 {
		return "", fmt.Errorf("archive must contain SKILL.md at root or in a single top-level directory")
	}

	candidate := filepath.Join(extractedDir, dirs[0].Name())
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
	reader, err := zip.OpenReader(src)
	if err != nil {
		return fmt.Errorf("failed to open zip archive: %w", err)
	}
	defer reader.Close()

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

		size := int64(file.UncompressedSize64)
		if size > limits.MaxFileBytes {
			return fmt.Errorf("archive file exceeds max file bytes: %s", file.Name)
		}
		totalBytes += size
		if totalBytes > limits.MaxTotalBytes {
			return fmt.Errorf("archive exceeds max total bytes: %d", limits.MaxTotalBytes)
		}

		if err := writeZipFile(file, path, limits.MaxFileBytes); err != nil {
			return err
		}
	}

	return nil
}

func writeZipFile(file *zip.File, outPath string, maxBytes int64) error {
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return fmt.Errorf("failed to create parent directory: %w", err)
	}

	rc, err := file.Open()
	if err != nil {
		return fmt.Errorf("failed to open archive file %s: %w", file.Name, err)
	}
	defer rc.Close()

	out, err := os.OpenFile(outPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("failed to create output file %s: %w", outPath, err)
	}
	defer out.Close()

	limited := io.LimitReader(rc, maxBytes+1)
	written, err := io.Copy(out, limited)
	if err != nil {
		return fmt.Errorf("failed to extract file %s: %w", file.Name, err)
	}
	if written > maxBytes {
		return fmt.Errorf("archive file exceeds max file bytes during extraction: %s", file.Name)
	}
	return nil
}

func extractTar(src, dest string, limits Limits) error {
	file, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open tar archive: %w", err)
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

		if header.Size > limits.MaxFileBytes {
			return fmt.Errorf("archive file exceeds max file bytes: %s", header.Name)
		}
		totalBytes += header.Size
		if totalBytes > limits.MaxTotalBytes {
			return fmt.Errorf("archive exceeds max total bytes: %d", limits.MaxTotalBytes)
		}

		if err := writeTarFile(header, tarReader, path, limits.MaxFileBytes); err != nil {
			return err
		}
	}

	return nil
}

func writeTarFile(header *tar.Header, tarReader *tar.Reader, outPath string, maxBytes int64) error {
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return fmt.Errorf("failed to create parent directory: %w", err)
	}

	out, err := os.OpenFile(outPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("failed to create output file %s: %w", outPath, err)
	}
	defer out.Close()

	limited := io.LimitReader(tarReader, maxBytes+1)
	written, err := io.Copy(out, limited)
	if err != nil {
		return fmt.Errorf("failed to extract file %s: %w", header.Name, err)
	}
	if written > maxBytes {
		return fmt.Errorf("archive file exceeds max file bytes during extraction: %s", header.Name)
	}
	return nil
}

func safeJoin(root, name string) (string, error) {
	normalized := strings.ReplaceAll(name, "\\", "/")
	if strings.HasPrefix(normalized, "/") || filepath.IsAbs(name) || hasWindowsDrivePrefix(normalized) {
		return "", fmt.Errorf("%s: archive contains absolute path: %s", ruleArchivePathEscape, name)
	}
	cleanName := path.Clean(normalized)
	if cleanName == "." {
		return "", fmt.Errorf("archive contains invalid path: %s", name)
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
