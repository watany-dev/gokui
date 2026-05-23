package app

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestAutomationErrorCodesUniqueAndFormat(t *testing.T) {
	codes := []string{
		inspectErrorCodeArgsInvalid,
		inspectErrorCodeSourceNotFound,
		inspectErrorCodeSourceInvalid,
		inspectErrorCodeSourcePrepareFailed,
		inspectErrorCodeScanFailed,
		inspectErrorCodeUnknown,

		fetchErrorCodeArgsInvalid,
		fetchErrorCodeSourceUnsupported,
		fetchErrorCodeSourceInvalid,
		fetchErrorCodeSourceRefNotPinned,
		fetchErrorCodeSourceDownloadFailed,
		fetchErrorCodeSkillInvalid,
		fetchErrorCodeOutputPrepareFailed,
		fetchErrorCodeCopyFailed,
		fetchErrorCodeDigestFailed,
		fetchErrorCodeMetadataWriteFailed,
		fetchErrorCodeUnknown,

		installErrorCodeArgsInvalid,
		installErrorCodeProfileUnsupported,
		installErrorCodeSourceNotFound,
		installErrorCodeSourcePrepareFailed,
		installErrorCodeEvaluationFailed,
		installErrorCodeSourceMetadataFailed,
		installErrorCodeTargetInvalid,
		installErrorCodeTargetPrepareFailed,
		installErrorCodeWriteFailed,
		installErrorCodePolicyRejected,
		installErrorCodeUnknown,

		lockVerifyErrorCodeReadLockfile,
		lockVerifyErrorCodeInvalidLockfile,
		lockVerifyErrorCodeDigestFailed,
		lockVerifyErrorCodeUnknown,

		updateCodeUpToDate,
		updateCodeChanged,
		updateCodePolicyRejected,
		updateCodeGitHubRefFloating,
		updateCodeLockfileInvalid,
		updateCodeGitHubSourceBad,
		updateCodeSourceMetadataBad,
		updateCodeSourcePrepareError,
		updateCodeEvaluationError,

		updateFatalCodeArgsInvalid,
		updateFatalCodeTargetInvalid,
		updateFatalCodeTargetReadFail,
		updateFatalCodeReportBuild,
		updateFatalCodeUnknown,
	}

	pattern := regexp.MustCompile(`^[A-Z0-9_]+$`)
	seen := map[string]struct{}{}
	for _, code := range codes {
		if code == "" {
			t.Fatal("error_code must not be empty")
		}
		if !pattern.MatchString(code) {
			t.Fatalf("error_code has invalid format: %q", code)
		}
		if _, ok := seen[code]; ok {
			t.Fatalf("duplicate error_code detected: %q", code)
		}
		seen[code] = struct{}{}
	}
}

func TestLockVerifyCheckCodesUniqueAndFormat(t *testing.T) {
	codes := []string{
		lockVerifyCodeSchema,
		lockVerifyCodeName,
		lockVerifyCodeStructure,
		lockVerifyCodeSource,
		lockVerifyCodeSourceMetadata,
		lockVerifyCodeInstallReport,
		lockVerifyCodeFileDigests,
		lockVerifyCodeRootHash,
	}

	pattern := regexp.MustCompile(`^[A-Z0-9_]+$`)
	seen := map[string]struct{}{}
	for _, code := range codes {
		if code == "" {
			t.Fatal("lock verify check code must not be empty")
		}
		if !pattern.MatchString(code) {
			t.Fatalf("lock verify check code has invalid format: %q", code)
		}
		if _, ok := seen[code]; ok {
			t.Fatalf("duplicate lock verify check code detected: %q", code)
		}
		seen[code] = struct{}{}
	}
}

func TestAutomationErrorCodesDocumentedInREADME(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)

	codes := []string{
		inspectErrorCodeArgsInvalid,
		inspectErrorCodeSourceNotFound,
		inspectErrorCodeSourceInvalid,
		inspectErrorCodeSourcePrepareFailed,
		inspectErrorCodeScanFailed,
		inspectErrorCodeUnknown,

		fetchErrorCodeArgsInvalid,
		fetchErrorCodeSourceUnsupported,
		fetchErrorCodeSourceInvalid,
		fetchErrorCodeSourceRefNotPinned,
		fetchErrorCodeSourceDownloadFailed,
		fetchErrorCodeSkillInvalid,
		fetchErrorCodeOutputPrepareFailed,
		fetchErrorCodeCopyFailed,
		fetchErrorCodeDigestFailed,
		fetchErrorCodeMetadataWriteFailed,
		fetchErrorCodeUnknown,

		installErrorCodeArgsInvalid,
		installErrorCodeProfileUnsupported,
		installErrorCodeSourceNotFound,
		installErrorCodeSourcePrepareFailed,
		installErrorCodeEvaluationFailed,
		installErrorCodeSourceMetadataFailed,
		installErrorCodeTargetInvalid,
		installErrorCodeTargetPrepareFailed,
		installErrorCodeWriteFailed,
		installErrorCodePolicyRejected,
		installErrorCodeUnknown,

		lockVerifyErrorCodeReadLockfile,
		lockVerifyErrorCodeInvalidLockfile,
		lockVerifyErrorCodeDigestFailed,
		lockVerifyErrorCodeUnknown,

		updateCodeUpToDate,
		updateCodeChanged,
		updateCodePolicyRejected,
		updateCodeGitHubRefFloating,
		updateCodeLockfileInvalid,
		updateCodeGitHubSourceBad,
		updateCodeSourceMetadataBad,
		updateCodeSourcePrepareError,
		updateCodeEvaluationError,

		updateFatalCodeArgsInvalid,
		updateFatalCodeTargetInvalid,
		updateFatalCodeTargetReadFail,
		updateFatalCodeReportBuild,
		updateFatalCodeUnknown,
	}

	for _, code := range codes {
		if !strings.Contains(readme, "`"+code+"`") {
			t.Fatalf("README.md is missing documented error_code: %s", code)
		}
	}
}
