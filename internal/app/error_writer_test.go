package app

import (
	"errors"
	"strings"
	"testing"
)

type failingWriteSink struct{}

func (failingWriteSink) Write(_ []byte) (int, error) {
	return 0, errors.New("synthetic write failure")
}

func TestStructuredErrorWritersHandleStdoutWriteFailure(t *testing.T) {
	t.Run("inspect json", func(t *testing.T) {
		var stderr strings.Builder
		code := writeInspectJSONError(failingWriteSink{}, &stderr, inspectErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
			ErrorCode:     inspectErrorCodeSourceNotFound,
			Message:       "inspect source not found",
			Source:        source{Input: "/tmp/missing", Kind: "local-dir"},
			Note:          "test",
		})
		if code != 1 {
			t.Fatalf("inspect json write failure not handled: code=%d stderr=%q", code, stderr.String())
		}
	})

	t.Run("inspect sarif", func(t *testing.T) {
		var stderr strings.Builder
		code := writeInspectSARIFError(failingWriteSink{}, &stderr, inspectErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
			ErrorCode:     inspectErrorCodeSourceNotFound,
			Message:       "inspect source not found",
			Source:        source{Input: "/tmp/missing", Kind: "local-dir"},
			Note:          "test",
		})
		if code != 1 {
			t.Fatalf("inspect sarif write failure not handled: code=%d stderr=%q", code, stderr.String())
		}
	})

	t.Run("fetch json", func(t *testing.T) {
		var stderr strings.Builder
		code := writeFetchJSONError(failingWriteSink{}, &stderr, fetchErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
			ErrorCode:     fetchErrorCodeSourceInvalid,
			Message:       "invalid source",
			Source:        source{Input: "bad", Kind: "github-source"},
			Output:        "/tmp/out",
			Note:          "test",
		})
		if code != 1 {
			t.Fatalf("fetch json write failure not handled: code=%d stderr=%q", code, stderr.String())
		}
	})

	t.Run("fetch sarif", func(t *testing.T) {
		var stderr strings.Builder
		code := writeFetchSARIFError(failingWriteSink{}, &stderr, fetchErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
			ErrorCode:     fetchErrorCodeSourceInvalid,
			Message:       "invalid source",
			Source:        source{Input: "bad", Kind: "github-source"},
			Output:        "/tmp/out",
			Note:          "test",
		})
		if code != 1 {
			t.Fatalf("fetch sarif write failure not handled: code=%d stderr=%q", code, stderr.String())
		}
	})

	t.Run("install json", func(t *testing.T) {
		var stderr strings.Builder
		code := writeInstallJSONError(failingWriteSink{}, &stderr, installErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
			ErrorCode:     installErrorCodeWriteFailed,
			Message:       "write failed",
			Source:        source{Input: "/tmp/skill", Kind: "local-dir"},
			Target:        "custom:/tmp/skills",
			PolicyProfile: policyProfileStrict,
			Note:          "test",
		})
		if code != 1 {
			t.Fatalf("install json write failure not handled: code=%d stderr=%q", code, stderr.String())
		}
	})

	t.Run("install sarif", func(t *testing.T) {
		var stderr strings.Builder
		code := writeInstallSARIFError(failingWriteSink{}, &stderr, installErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
			ErrorCode:     installErrorCodeWriteFailed,
			Message:       "write failed",
			Source:        source{Input: "/tmp/skill", Kind: "local-dir"},
			Target:        "custom:/tmp/skills",
			PolicyProfile: policyProfileStrict,
			Note:          "test",
		})
		if code != 1 {
			t.Fatalf("install sarif write failure not handled: code=%d stderr=%q", code, stderr.String())
		}
	})

	t.Run("update json", func(t *testing.T) {
		var stderr strings.Builder
		code := writeUpdateJSONError(failingWriteSink{}, &stderr, updateErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
			ErrorCode:     updateFatalCodeReportBuild,
			Message:       "report build failed",
			Target:        "/tmp/skills",
			Note:          "test",
		})
		if code != 1 {
			t.Fatalf("update json write failure not handled: code=%d stderr=%q", code, stderr.String())
		}
	})

	t.Run("update sarif", func(t *testing.T) {
		var stderr strings.Builder
		code := writeUpdateSARIFError(failingWriteSink{}, &stderr, updateErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
			ErrorCode:     updateFatalCodeReportBuild,
			Message:       "report build failed",
			Target:        "/tmp/skills",
			Note:          "test",
		})
		if code != 1 {
			t.Fatalf("update sarif write failure not handled: code=%d stderr=%q", code, stderr.String())
		}
	})

	t.Run("lock verify json", func(t *testing.T) {
		var stderr strings.Builder
		code := writeLockVerifyJSONError(failingWriteSink{}, &stderr, lockVerifyErrorReport{
			SchemaVersion: reportSchemaVersion,
			SkillPath:     "/tmp/skill",
			Status:        "ERROR",
			ErrorCode:     lockVerifyErrorCodeUnknown,
			Message:       "lock verify failed",
			Note:          "test",
		})
		if code != 1 {
			t.Fatalf("lock verify json write failure not handled: code=%d stderr=%q", code, stderr.String())
		}
	})

	t.Run("lock verify sarif", func(t *testing.T) {
		var stderr strings.Builder
		code := writeLockVerifySARIFError(failingWriteSink{}, &stderr, lockVerifyErrorReport{
			SchemaVersion: reportSchemaVersion,
			SkillPath:     "/tmp/skill",
			Status:        "ERROR",
			ErrorCode:     lockVerifyErrorCodeUnknown,
			Message:       "lock verify failed",
			Note:          "test",
		})
		if code != 1 {
			t.Fatalf("lock verify sarif write failure not handled: code=%d stderr=%q", code, stderr.String())
		}
	})
}
