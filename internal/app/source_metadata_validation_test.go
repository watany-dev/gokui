package app

import (
	"strings"
	"testing"
	"testing/quick"
)

func TestSourceMetadataValidationHelpers(t *testing.T) {
	t.Run("validate metadata errors", func(t *testing.T) {
		cases := []sourceMetadata{
			{},
			{
				Schema: "gokui.source/v1",
			},
			{
				Schema:      "gokui.source/v1",
				SourceInput: "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			},
			{
				Schema:      "gokui.source/v1",
				SourceInput: "github:org/repo/path@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:  "github-source",
			},
			{
				Schema:      "gokui.source/v1",
				SourceInput: "github:org/repo//skills/x@main",
				SourceKind:  "github-source",
			},
			{
				Schema:      "gokui.source/v1",
				SourceInput: "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:  "github-source",
				ResolvedRef: "main",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/./x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo// skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills//x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:owner/repo.git//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:Owner/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:owner/Repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:owner/.repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:owner/repo.//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:owner/re..po//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/x@shadow@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills:x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/con@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/COM¹.txt@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/\u202edemo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/\u200bdemo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/my skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f90\u00a01234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f90\u200b1234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f90\u202e1234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f90\U000E00011234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f90\ufe0f1234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:or\u00a0g/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/re\u200bpo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:or\U000E0001g/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/re\ufe0fpo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/ x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/x.@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:      "gokui.source/v1",
				SourceInput: "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:  "github-source",
				ResolvedRef: "abcdef0",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     " github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8F3C2D1A4B5C6D7E8F901234567890ABCDEF1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234 ",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "not-a-time",
				SkillRootSHA256: "abc",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "zz",
			},
		}
		for _, c := range cases {
			if err := validateSourceMetadata(c); err == nil {
				t.Fatalf("expected validation error for %+v", c)
			}
		}
	})

	t.Run("validate metadata never panics on random inputs", func(t *testing.T) {
		prop := func(meta sourceMetadata) (ok bool) {
			defer func() {
				if recover() != nil {
					ok = false
				}
			}()
			_ = validateSourceMetadata(meta)
			return true
		}
		if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
			t.Fatalf("validateSourceMetadata panic-safety property failed: %v", err)
		}
	})

	t.Run("validate metadata rejects non-utf8 source input", func(t *testing.T) {
		sourceInput := "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"
		invalidSourceInput := string(append([]byte(sourceInput), 0xff))
		err := validateSourceMetadata(sourceMetadata{
			Schema:          "gokui.source/v1",
			SourceInput:     invalidSourceInput,
			SourceKind:      "github-source",
			ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			FetchedAt:       "2026-05-23T00:00:00Z",
			SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		})
		if err == nil {
			t.Fatal("expected invalid source_input utf-8 error")
		}
		if !strings.Contains(err.Error(), "source metadata has invalid github source input") {
			t.Fatalf("expected metadata source_input context, got %v", err)
		}
		if !strings.Contains(err.Error(), "github source must be valid UTF-8") {
			t.Fatalf("expected utf-8 validation detail, got %v", err)
		}
	})

	t.Run("validate metadata rejects C0/C1 controls with explicit errors", func(t *testing.T) {
		valid := sourceMetadata{
			Schema:          "gokui.source/v1",
			SourceInput:     "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			SourceKind:      "github-source",
			ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			FetchedAt:       "2026-05-23T00:00:00Z",
			SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		}
		cases := []struct {
			name       string
			mutate     func(*sourceMetadata)
			detailPart string
		}{
			{
				name: "schema has C0/C1 control",
				mutate: func(m *sourceMetadata) {
					m.Schema = "gokui.source/v1\u008f"
				},
				detailPart: "schema must not contain C0/C1 control characters",
			},
			{
				name: "schema has C0/C1 control at edge",
				mutate: func(m *sourceMetadata) {
					m.Schema = "\u0085gokui.source/v1"
				},
				detailPart: "schema must not contain C0/C1 control characters",
			},
			{
				name: "schema has C0/C1 control only",
				mutate: func(m *sourceMetadata) {
					m.Schema = "\u0085"
				},
				detailPart: "schema must not contain C0/C1 control characters",
			},
			{
				name: "schema has C0 NUL control only",
				mutate: func(m *sourceMetadata) {
					m.Schema = "\u0000"
				},
				detailPart: "schema must not contain C0/C1 control characters",
			},
			{
				name: "schema has DEL control only",
				mutate: func(m *sourceMetadata) {
					m.Schema = "\u007f"
				},
				detailPart: "schema must not contain C0/C1 control characters",
			},
			{
				name: "schema has DEL control at edge",
				mutate: func(m *sourceMetadata) {
					m.Schema = "\u007fgokui.source/v1"
				},
				detailPart: "schema must not contain C0/C1 control characters",
			},
			{
				name: "schema has surrounding whitespace",
				mutate: func(m *sourceMetadata) {
					m.Schema = " gokui.source/v1 "
				},
				detailPart: "schema must not contain leading or trailing whitespace",
			},
			{
				name: "source_input has C0/C1 control",
				mutate: func(m *sourceMetadata) {
					m.SourceInput = "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef12\u008f4"
				},
				detailPart: "source_input must not contain C0/C1 control characters",
			},
			{
				name: "source_input has C0/C1 control at edge",
				mutate: func(m *sourceMetadata) {
					m.SourceInput = "\u0085github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"
				},
				detailPart: "source_input must not contain C0/C1 control characters",
			},
			{
				name: "source_input has C0/C1 control only",
				mutate: func(m *sourceMetadata) {
					m.SourceInput = "\u0085"
				},
				detailPart: "source_input must not contain C0/C1 control characters",
			},
			{
				name: "source_input has C0 NUL control only",
				mutate: func(m *sourceMetadata) {
					m.SourceInput = "\u0000"
				},
				detailPart: "source_input must not contain C0/C1 control characters",
			},
			{
				name: "source_input has DEL control only",
				mutate: func(m *sourceMetadata) {
					m.SourceInput = "\u007f"
				},
				detailPart: "source_input must not contain C0/C1 control characters",
			},
			{
				name: "source_input has DEL control at edge",
				mutate: func(m *sourceMetadata) {
					m.SourceInput = "\u007fgithub:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"
				},
				detailPart: "source_input must not contain C0/C1 control characters",
			},
			{
				name: "source_kind has C0/C1 control",
				mutate: func(m *sourceMetadata) {
					m.SourceKind = "github-source\u008f"
				},
				detailPart: "source_kind must not contain C0/C1 control characters",
			},
			{
				name: "source_kind has C0/C1 control only",
				mutate: func(m *sourceMetadata) {
					m.SourceKind = "\u0085"
				},
				detailPart: "source_kind must not contain C0/C1 control characters",
			},
			{
				name: "source_kind has C0 NUL control only",
				mutate: func(m *sourceMetadata) {
					m.SourceKind = "\u0000"
				},
				detailPart: "source_kind must not contain C0/C1 control characters",
			},
			{
				name: "source_kind has DEL control only",
				mutate: func(m *sourceMetadata) {
					m.SourceKind = "\u007f"
				},
				detailPart: "source_kind must not contain C0/C1 control characters",
			},
			{
				name: "source_kind has DEL control at edge",
				mutate: func(m *sourceMetadata) {
					m.SourceKind = "\u007fgithub-source"
				},
				detailPart: "source_kind must not contain C0/C1 control characters",
			},
			{
				name: "source_kind is empty",
				mutate: func(m *sourceMetadata) {
					m.SourceKind = ""
				},
				detailPart: "source_kind is empty",
			},
			{
				name: "source_kind has surrounding whitespace",
				mutate: func(m *sourceMetadata) {
					m.SourceKind = " github-source "
				},
				detailPart: "source_kind must not contain leading or trailing whitespace",
			},
			{
				name: "source_kind must be canonical lowercase",
				mutate: func(m *sourceMetadata) {
					m.SourceKind = "GitHub-Source"
				},
				detailPart: "source_kind must be canonical lowercase",
			},
			{
				name: "resolved_ref has C0/C1 control",
				mutate: func(m *sourceMetadata) {
					m.ResolvedRef = "8f3c2d1a4b5c6d7e8f901234567890abcdef12\u008f4"
				},
				detailPart: "resolved_ref must not contain C0/C1 control characters",
			},
			{
				name: "resolved_ref has C0/C1 control only",
				mutate: func(m *sourceMetadata) {
					m.ResolvedRef = "\u0085"
				},
				detailPart: "resolved_ref must not contain C0/C1 control characters",
			},
			{
				name: "resolved_ref has C0 NUL control only",
				mutate: func(m *sourceMetadata) {
					m.ResolvedRef = "\u0000"
				},
				detailPart: "resolved_ref must not contain C0/C1 control characters",
			},
			{
				name: "resolved_ref has DEL control only",
				mutate: func(m *sourceMetadata) {
					m.ResolvedRef = "\u007f"
				},
				detailPart: "resolved_ref must not contain C0/C1 control characters",
			},
			{
				name: "resolved_ref has DEL control at edge",
				mutate: func(m *sourceMetadata) {
					m.ResolvedRef = "\u007f8f3c2d1a4b5c6d7e8f901234567890abcdef1234"
				},
				detailPart: "resolved_ref must not contain C0/C1 control characters",
			},
			{
				name: "fetched_at has C0/C1 control",
				mutate: func(m *sourceMetadata) {
					m.FetchedAt = "2026-05-23T00:00:00\u008fZ"
				},
				detailPart: "fetched_at must not contain C0/C1 control characters",
			},
			{
				name: "fetched_at has C0/C1 control only",
				mutate: func(m *sourceMetadata) {
					m.FetchedAt = "\u0085"
				},
				detailPart: "fetched_at must not contain C0/C1 control characters",
			},
			{
				name: "fetched_at has C0 NUL control only",
				mutate: func(m *sourceMetadata) {
					m.FetchedAt = "\u0000"
				},
				detailPart: "fetched_at must not contain C0/C1 control characters",
			},
			{
				name: "fetched_at has DEL control only",
				mutate: func(m *sourceMetadata) {
					m.FetchedAt = "\u007f"
				},
				detailPart: "fetched_at must not contain C0/C1 control characters",
			},
			{
				name: "fetched_at has DEL control at edge",
				mutate: func(m *sourceMetadata) {
					m.FetchedAt = "\u007f2026-05-23T00:00:00Z"
				},
				detailPart: "fetched_at must not contain C0/C1 control characters",
			},
			{
				name: "fetched_at has surrounding whitespace",
				mutate: func(m *sourceMetadata) {
					m.FetchedAt = " 2026-05-23T00:00:00Z "
				},
				detailPart: "fetched_at must not contain leading or trailing whitespace",
			},
			{
				name: "skill_root_sha256 has C0/C1 control",
				mutate: func(m *sourceMetadata) {
					m.SkillRootSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\u008f"
				},
				detailPart: "skill_root_sha256 must not contain C0/C1 control characters",
			},
			{
				name: "skill_root_sha256 has C0/C1 control only",
				mutate: func(m *sourceMetadata) {
					m.SkillRootSHA256 = "\u0085"
				},
				detailPart: "skill_root_sha256 must not contain C0/C1 control characters",
			},
			{
				name: "skill_root_sha256 has C0 NUL control only",
				mutate: func(m *sourceMetadata) {
					m.SkillRootSHA256 = "\u0000"
				},
				detailPart: "skill_root_sha256 must not contain C0/C1 control characters",
			},
			{
				name: "skill_root_sha256 has DEL control only",
				mutate: func(m *sourceMetadata) {
					m.SkillRootSHA256 = "\u007f"
				},
				detailPart: "skill_root_sha256 must not contain C0/C1 control characters",
			},
			{
				name: "skill_root_sha256 has DEL control at edge",
				mutate: func(m *sourceMetadata) {
					m.SkillRootSHA256 = "\u007faaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				},
				detailPart: "skill_root_sha256 must not contain C0/C1 control characters",
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				mut := valid
				tc.mutate(&mut)
				err := validateSourceMetadata(mut)
				if err == nil || !strings.Contains(err.Error(), tc.detailPart) {
					t.Fatalf("expected validation detail %q, got err=%v", tc.detailPart, err)
				}
			})
		}
	})

	t.Run("validate metadata rejects source_input unicode obfuscation with explicit error", func(t *testing.T) {
		err := validateSourceMetadata(sourceMetadata{
			Schema:          "gokui.source/v1",
			SourceInput:     "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef12\u200d34",
			SourceKind:      "github-source",
			ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			FetchedAt:       "2026-05-23T00:00:00Z",
			SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		})
		if err == nil || !strings.Contains(err.Error(), "source_input must not contain Unicode bidi, zero-width, tag, or variation-selector characters") {
			t.Fatalf("expected source_input unicode-obfuscation validation error, got %v", err)
		}
	})

	t.Run("validate metadata rejects unicode obfuscation characters with explicit errors", func(t *testing.T) {
		valid := sourceMetadata{
			Schema:          "gokui.source/v1",
			SourceInput:     "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			SourceKind:      "github-source",
			ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			FetchedAt:       "2026-05-23T00:00:00Z",
			SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		}
		cases := []struct {
			name       string
			mutate     func(*sourceMetadata)
			detailPart string
		}{
			{
				name: "schema has bidi control",
				mutate: func(m *sourceMetadata) {
					m.Schema = "gokui.source/v1\u202e"
				},
				detailPart: "schema must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
			},
			{
				name: "source_kind has zero-width character",
				mutate: func(m *sourceMetadata) {
					m.SourceKind = "github-source\u200d"
				},
				detailPart: "source_kind must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
			},
			{
				name: "resolved_ref has zero-width character",
				mutate: func(m *sourceMetadata) {
					m.ResolvedRef = "8f3c2d1a4b5c6d7e8f901234567890abcdef12\u200d34"
				},
				detailPart: "resolved_ref must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
			},
			{
				name: "fetched_at has tag character",
				mutate: func(m *sourceMetadata) {
					m.FetchedAt = "2026-05-23T00:00:00Z\U000E0001"
				},
				detailPart: "fetched_at must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
			},
			{
				name: "skill_root_sha256 has variation selector",
				mutate: func(m *sourceMetadata) {
					m.SkillRootSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\ufe0f"
				},
				detailPart: "skill_root_sha256 must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				mut := valid
				tc.mutate(&mut)
				err := validateSourceMetadata(mut)
				if err == nil || !strings.Contains(err.Error(), tc.detailPart) {
					t.Fatalf("expected validation detail %q, got err=%v", tc.detailPart, err)
				}
			})
		}
	})
}
