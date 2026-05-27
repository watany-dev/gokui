package scan

import "testing"

func TestClassifyURLRisks(t *testing.T) {
	line := "visit https://bit.ly/example and https://192.168.1.44:8443/setup and https://pastebin.com/x and https://github.com/org/repo/releases/download/v1.0.0/a.tgz and ![x](https://example.com/x.png) and https://example.com"
	findings := classifyURLRisks(line, "SKILL.md", 12, true)

	assertHasID(t, findings, "URL_SHORTENER")
	assertHasID(t, findings, "RAW_IP_URL")
	assertHasID(t, findings, "PASTE_SITE_URL")
	assertHasID(t, findings, "RELEASE_ASSET_URL")
	assertHasID(t, findings, "REMOTE_IMAGE_URL")
}

func TestClassifyURLRisksEdgeCases(t *testing.T) {
	t.Run("returns nil for non-url line", func(t *testing.T) {
		if findings := classifyURLRisks("echo safe", "SKILL.md", 1, true); findings != nil {
			t.Fatalf("expected nil findings for non-url line, got %+v", findings)
		}
	})

	t.Run("ignores malformed and hostless URLs", func(t *testing.T) {
		line := "bad https://[::1 and hostless https:///path only"
		findings := classifyURLRisks(line, "SKILL.md", 2, true)
		if len(findings) != 0 {
			t.Fatalf("expected no findings for malformed/hostless URLs, got %+v", findings)
		}
	})

	t.Run("normalizes shortener host case", func(t *testing.T) {
		line := "open https://BIT.LY/abc"
		findings := classifyURLRisks(line, "SKILL.md", 3, true)
		assertHasID(t, findings, "URL_SHORTENER")
	})

	t.Run("does not flag remote image outside markdown context", func(t *testing.T) {
		line := "curl https://example.com/image.png"
		findings := classifyURLRisks(line, "script.sh", 4, false)
		for _, f := range findings {
			if f.ID == "REMOTE_IMAGE_URL" {
				t.Fatalf("unexpected REMOTE_IMAGE_URL finding: %+v", findings)
			}
		}
	})

	t.Run("detects scheme-relative URL risks", func(t *testing.T) {
		line := "visit //bit.ly/example and //192.168.1.44:8443/setup and ![x](//example.com/x.png)"
		findings := classifyURLRisks(line, "SKILL.md", 5, true)
		assertHasID(t, findings, "URL_SHORTENER")
		assertHasID(t, findings, "RAW_IP_URL")
		assertHasID(t, findings, "REMOTE_IMAGE_URL")
	})

	t.Run("detects bracketed IPv6 URL risks", func(t *testing.T) {
		line := "visit https://[2001:db8::1]/setup and //[2001:db8::2]/boot and ![x](https://[2001:db8::3]/x.png)"
		findings := classifyURLRisks(line, "SKILL.md", 6, true)
		assertHasID(t, findings, "RAW_IP_URL")
		assertHasID(t, findings, "REMOTE_IMAGE_URL")
	})

	t.Run("detects bracketed ipv6 zone-id URL risks", func(t *testing.T) {
		line := "visit https://[fe80::1%25eth0]/setup and //[fe80::2%25eth0]/boot"
		findings := classifyURLRisks(line, "SKILL.md", 7, true)
		assertHasID(t, findings, "RAW_IP_URL")
	})

	t.Run("detects decimal-encoded ipv4 URL risks", func(t *testing.T) {
		line := "visit https://3232235777/setup"
		findings := classifyURLRisks(line, "SKILL.md", 8, true)
		assertHasID(t, findings, "RAW_IP_URL")
	})

	t.Run("detects hex-and-octal-encoded ipv4 URL risks", func(t *testing.T) {
		line := "visit https://0xC0A80101/setup and https://030052000401/setup"
		findings := classifyURLRisks(line, "SKILL.md", 9, true)
		assertHasID(t, findings, "RAW_IP_URL")
	})

	t.Run("detects dotted mixed-base ipv4 URL risks", func(t *testing.T) {
		line := "visit https://0xc0.0xa8.0x01.0x01/setup and https://0300.0250.0001.0001/setup"
		findings := classifyURLRisks(line, "SKILL.md", 10, true)
		assertHasID(t, findings, "RAW_IP_URL")
	})

	t.Run("detects abbreviated dotted ipv4 URL risks", func(t *testing.T) {
		line := "visit https://127.1/setup and https://10.1.2/bootstrap"
		findings := classifyURLRisks(line, "SKILL.md", 11, true)
		assertHasID(t, findings, "RAW_IP_URL")
	})

	t.Run("normalizes trailing-dot and idna-dot-variant hosts", func(t *testing.T) {
		line := "open https://bit.ly./x and https://bit。ly/x and https://192.168.1.44./setup and https://github.com./org/repo/releases/download/v1.0.0/a.tgz"
		findings := classifyURLRisks(line, "SKILL.md", 12, true)
		assertHasID(t, findings, "URL_SHORTENER")
		assertHasID(t, findings, "RAW_IP_URL")
		assertHasID(t, findings, "RELEASE_ASSET_URL")
	})

	t.Run("normalizes leading www risk hosts", func(t *testing.T) {
		line := "open https://www.bit.ly/x and https://www.pastebin.com/x and https://www.github.com/org/repo/releases/download/v1.0.0/a.tgz"
		findings := classifyURLRisks(line, "SKILL.md", 13, true)
		assertHasID(t, findings, "URL_SHORTENER")
		assertHasID(t, findings, "PASTE_SITE_URL")
		assertHasID(t, findings, "RELEASE_ASSET_URL")
	})

	t.Run("matches configured risk-host subdomains but not lookalikes", func(t *testing.T) {
		line := "open https://x.bit.ly/a and https://raw.pastebin.com/b and https://evilbit.ly.com/c"
		findings := classifyURLRisks(line, "SKILL.md", 14, true)
		assertHasID(t, findings, "URL_SHORTENER")
		assertHasID(t, findings, "PASTE_SITE_URL")
	})

	t.Run("does not flag lookalike domains outside configured set", func(t *testing.T) {
		line := "open https://evilbit.ly.com/c and https://pastebin.com.evil.example/x"
		findings := classifyURLRisks(line, "SKILL.md", 15, true)
		if len(findings) != 0 {
			t.Fatalf("expected no findings for lookalike domains, got %+v", findings)
		}
	})

	t.Run("detects github release-asset cdn url forms", func(t *testing.T) {
		line := "open https://github-releases.githubusercontent.com/owner/repo/releases/download/v1.0.0/a.tgz and https://objects.githubusercontent.com/github-production-release-asset-2e65be/123?x=y"
		findings := classifyURLRisks(line, "SKILL.md", 14, true)
		assertHasID(t, findings, "RELEASE_ASSET_URL")
	})

	t.Run("detects github api release-asset url forms", func(t *testing.T) {
		line := "open https://api.github.com/repos/org/repo/releases/assets/12345"
		findings := classifyURLRisks(line, "SKILL.md", 15, true)
		assertHasID(t, findings, "RELEASE_ASSET_URL")
	})

	t.Run("detects github api release-id asset url forms", func(t *testing.T) {
		line := "open https://api.github.com/repos/org/repo/releases/123456/assets"
		findings := classifyURLRisks(line, "SKILL.md", 16, true)
		assertHasID(t, findings, "RELEASE_ASSET_URL")
	})

	t.Run("detects github uploads release-id asset url forms", func(t *testing.T) {
		line := "open https://uploads.github.com/repos/org/repo/releases/123456/assets?name=tool.tgz"
		findings := classifyURLRisks(line, "SKILL.md", 17, true)
		assertHasID(t, findings, "RELEASE_ASSET_URL")
	})

	t.Run("detects github latest release download url forms", func(t *testing.T) {
		line := "open https://github.com/org/repo/releases/latest/download/tool.tgz"
		findings := classifyURLRisks(line, "SKILL.md", 18, true)
		assertHasID(t, findings, "RELEASE_ASSET_URL")
	})

	t.Run("does not detect malformed github api release-asset url forms", func(t *testing.T) {
		line := "open https://api.github.com/repos/org/repo/releases/assets/not-a-number and https://uploads.github.com/repos/org/repo/releases/assets/12345"
		findings := classifyURLRisks(line, "SKILL.md", 19, true)
		if len(findings) != 0 {
			t.Fatalf("expected no findings for malformed release-asset forms, got %+v", findings)
		}
	})
}

func TestExtractURLCandidates(t *testing.T) {
	t.Run("collects both standard and bracketed ipv6 urls", func(t *testing.T) {
		line := "https://example.com and https://[2001:db8::1]/x and //[2001:db8::2]/y"
		got := extractURLCandidates(line)
		if len(got) < 3 {
			t.Fatalf("expected at least three URL candidates, got %+v", got)
		}
	})

	t.Run("deduplicates overlapping matches", func(t *testing.T) {
		line := "https://[2001:db8::1]/x"
		got := extractURLCandidates(line)
		if len(got) != 1 {
			t.Fatalf("expected one deduplicated URL candidate, got %+v", got)
		}
	})

	t.Run("returns nil when no url candidates exist", func(t *testing.T) {
		if got := extractURLCandidates("plain text"); got != nil {
			t.Fatalf("expected nil URL candidates, got %+v", got)
		}
	})
}

func TestNormalizeURLRiskHost(t *testing.T) {
	t.Run("normalizes trailing-dot and idna dot-variant hosts", func(t *testing.T) {
		if got := normalizeURLRiskHost("bit.ly."); got != "bit.ly" {
			t.Fatalf("expected trailing-dot normalization, got %q", got)
		}
		if got := normalizeURLRiskHost("bit。ly"); got != "bit.ly" {
			t.Fatalf("expected idna dot-variant normalization, got %q", got)
		}
	})

	t.Run("returns empty for empty input", func(t *testing.T) {
		if got := normalizeURLRiskHost(" \t "); got != "" {
			t.Fatalf("expected empty normalized host, got %q", got)
		}
	})
}

func TestParseRawIPHost(t *testing.T) {
	t.Run("parses plain ip and bracketed-ipv6 zone-id host values", func(t *testing.T) {
		if got := parseRawIPHost("192.168.1.44"); got == nil {
			t.Fatalf("expected ipv4 host parse to succeed")
		}
		if got := parseRawIPHost("fe80::1%eth0"); got == nil {
			t.Fatalf("expected ipv6 zone-id host parse to succeed")
		}
	})

	t.Run("returns nil for non-ip hosts", func(t *testing.T) {
		if got := parseRawIPHost("example.com"); got != nil {
			t.Fatalf("expected non-ip host parse to fail, got %v", got)
		}
	})
}

func TestIsGitHubReleaseAssetURL(t *testing.T) {
	t.Run("matches github release download and known cdn forms", func(t *testing.T) {
		if !isGitHubReleaseAssetURL("github.com", "/org/repo/releases/download/v1.0.0/a.tgz") {
			t.Fatal("expected github.com release download path to match")
		}
		if !isGitHubReleaseAssetURL("github.com", "/org/repo/releases/latest/download/tool.tgz") {
			t.Fatal("expected github.com releases/latest/download path to match")
		}
		if !isGitHubReleaseAssetURL("api.github.com", "/repos/org/repo/releases/assets/12345") {
			t.Fatal("expected api.github.com releases/assets path to match")
		}
		if !isGitHubReleaseAssetURL("api.github.com", "/repos/org/repo/releases/123456/assets") {
			t.Fatal("expected api.github.com releases/<id>/assets path to match")
		}
		if !isGitHubReleaseAssetURL("uploads.github.com", "/repos/org/repo/releases/123456/assets") {
			t.Fatal("expected uploads.github.com releases/<id>/assets path to match")
		}
		if !isGitHubReleaseAssetURL("github-releases.githubusercontent.com", "/asset/123") {
			t.Fatal("expected github-releases CDN host to match")
		}
		if !isGitHubReleaseAssetURL("objects.githubusercontent.com", "/github-production-release-asset-2e65be/123") {
			t.Fatal("expected objects CDN release asset path to match")
		}
	})

	t.Run("does not match unrelated githubusercontent paths", func(t *testing.T) {
		if isGitHubReleaseAssetURL("objects.githubusercontent.com", "/avatars/u/123?v=4") {
			t.Fatal("did not expect non-release objects path to match")
		}
	})

	t.Run("does not match non-numeric github api release-id asset paths", func(t *testing.T) {
		if isGitHubReleaseAssetURL("api.github.com", "/repos/org/repo/releases/not-a-number/assets") {
			t.Fatal("did not expect non-numeric releases/<id>/assets path to match")
		}
		if isGitHubReleaseAssetURL("uploads.github.com", "/repos/org/repo/releases/not-a-number/assets") {
			t.Fatal("did not expect non-numeric uploads releases/<id>/assets path to match")
		}
		if isGitHubReleaseAssetURL("api.github.com", "/repos/org/repo/releases/assets/not-a-number") {
			t.Fatal("did not expect non-numeric releases/assets/<id> path to match")
		}
		if isGitHubReleaseAssetURL("api.github.com", "/repos/org/repo/releases/assets/12345/extra") {
			t.Fatal("did not expect extra-path releases/assets/<id> path to match")
		}
		if isGitHubReleaseAssetURL("uploads.github.com", "/repos/org/repo/releases/assets/12345") {
			t.Fatal("did not expect uploads releases/assets/<id> path to match")
		}
	})
}

func TestParseIntegerIPv4Host(t *testing.T) {
	t.Run("parses decimal hex and octal ipv4 host values", func(t *testing.T) {
		for _, in := range []string{"3232235777", "0xC0A80101", "030052000401"} {
			got, ok := parseIntegerIPv4Host(in)
			if !ok || got == nil {
				t.Fatalf("expected integer ipv4 host parse to succeed for %q", in)
			}
			if got.String() != "192.168.1.1" {
				t.Fatalf("expected 192.168.1.1 from %q, got %q", in, got.String())
			}
		}
	})

	t.Run("rejects invalid or out-of-range integer host values", func(t *testing.T) {
		for _, in := range []string{"example.com", "4294967296", "089", "0x", "0xGG", "0x100000000"} {
			if _, ok := parseIntegerIPv4Host(in); ok {
				t.Fatalf("expected parse failure for %q", in)
			}
		}
	})
}

func TestParseDottedMixedBaseIPv4Host(t *testing.T) {
	t.Run("parses dotted mixed-base ipv4 host values", func(t *testing.T) {
		for _, in := range []string{"0xc0.0xa8.0x01.0x01", "0300.0250.0001.0001"} {
			got, ok := parseDottedMixedBaseIPv4Host(in)
			if !ok || got == nil {
				t.Fatalf("expected dotted mixed-base ipv4 host parse to succeed for %q", in)
			}
			if got.String() != "192.168.1.1" {
				t.Fatalf("expected 192.168.1.1 from %q, got %q", in, got.String())
			}
		}
	})

	t.Run("rejects invalid dotted mixed-base ipv4 host values", func(t *testing.T) {
		for _, in := range []string{"0xc0.0xa8.0x01", "0300.0250.0001.0001.1", "0xGG.0xa8.0x01.0x01"} {
			if _, ok := parseDottedMixedBaseIPv4Host(in); ok {
				t.Fatalf("expected parse failure for %q", in)
			}
		}
	})
}

func TestParseAbbreviatedDottedIPv4Host(t *testing.T) {
	t.Run("parses abbreviated dotted ipv4 host forms", func(t *testing.T) {
		cases := map[string]string{
			"127.1":  "127.0.0.1",
			"10.1.2": "10.1.0.2",
		}
		for in, want := range cases {
			got, ok := parseAbbreviatedDottedIPv4Host(in)
			if !ok || got == nil {
				t.Fatalf("expected abbreviated dotted ipv4 parse to succeed for %q", in)
			}
			if got.String() != want {
				t.Fatalf("expected %q from %q, got %q", want, in, got.String())
			}
		}
	})

	t.Run("rejects invalid abbreviated dotted ipv4 forms", func(t *testing.T) {
		for _, in := range []string{"1", "1.2.3.4", "1.2.3.4.5", "1.example", "1.16777216", "1.2.65536"} {
			if _, ok := parseAbbreviatedDottedIPv4Host(in); ok {
				t.Fatalf("expected parse failure for %q", in)
			}
		}
	})
}

func TestParseIPv4IntegerComponent(t *testing.T) {
	t.Run("parses decimal octal and hex components with bit limits", func(t *testing.T) {
		cases := []struct {
			in   string
			bits int
			want uint64
		}{
			{in: "255", bits: 16, want: 255},
			{in: "0377", bits: 16, want: 255},
			{in: "0xff", bits: 16, want: 255},
		}
		for _, tc := range cases {
			got, ok := parseIPv4IntegerComponent(tc.in, tc.bits)
			if !ok || got != tc.want {
				t.Fatalf("expected %q bits=%d to parse as %d, got %d (ok=%v)", tc.in, tc.bits, tc.want, got, ok)
			}
		}
	})

	t.Run("rejects invalid format and bit constraints", func(t *testing.T) {
		cases := []struct {
			in   string
			bits int
		}{
			{in: "", bits: 8},
			{in: "255", bits: 0},
			{in: "255", bits: 33},
			{in: "0x", bits: 16},
			{in: "0xGG", bits: 16},
			{in: "08", bits: 16},
			{in: "example", bits: 16},
			{in: "65536", bits: 16},
		}
		for _, tc := range cases {
			if _, ok := parseIPv4IntegerComponent(tc.in, tc.bits); ok {
				t.Fatalf("expected parse failure for %q bits=%d", tc.in, tc.bits)
			}
		}
	})
}

func TestParseIPv4OctetWithMixedBase(t *testing.T) {
	t.Run("parses decimal octal and hex octets", func(t *testing.T) {
		cases := map[string]uint64{
			"255":  255,
			"0377": 255,
			"0xff": 255,
		}
		for in, want := range cases {
			got, ok := parseIPv4OctetWithMixedBase(in)
			if !ok || got != want {
				t.Fatalf("expected %q to parse as %d, got %d (ok=%v)", in, want, got, ok)
			}
		}
	})

	t.Run("rejects invalid octet forms", func(t *testing.T) {
		for _, in := range []string{"", "256", "0x", "0xGG", "08"} {
			if _, ok := parseIPv4OctetWithMixedBase(in); ok {
				t.Fatalf("expected parse failure for %q", in)
			}
		}
	})
}

func TestParseURLHostAndTokenizeWords(t *testing.T) {
	t.Run("parseURLHost handles invalid and valid inputs", func(t *testing.T) {
		if host, ok := parseURLHost("://bad-url"); ok || host != "" {
			t.Fatalf("expected invalid url parse to fail, got host=%q ok=%v", host, ok)
		}
		if host, ok := parseURLHost("https:///path-only"); ok || host != "" {
			t.Fatalf("expected empty-host parse to fail, got host=%q ok=%v", host, ok)
		}
		if host, ok := parseURLHost(" https://Example.COM:8443/path "); !ok || host != "example.com" {
			t.Fatalf("expected normalized host example.com, got host=%q ok=%v", host, ok)
		}
	})

	t.Run("tokenizeWords splits on non-letters", func(t *testing.T) {
		if out := tokenizeWords(" \t "); out != nil {
			t.Fatalf("expected nil for blank line, got %+v", out)
		}
		out := tokenizeWords("Run_Bash-Setup 123, then EXECUTE!")
		want := []string{"run", "bash", "setup", "then", "execute"}
		if len(out) != len(want) {
			t.Fatalf("unexpected token count: got %+v want %+v", out, want)
		}
		for i := range want {
			if out[i] != want[i] {
				t.Fatalf("unexpected tokens: got %+v want %+v", out, want)
			}
		}
	})
}
