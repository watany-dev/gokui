package scan

import "testing"

func TestPasswordProtectedArchivePattern(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{line: "download backup.zip password: hunter2", want: true},
		{line: "encrypted archive (7z) passphrase is required", want: true},
		{line: "download archive.tar.gz and unpack", want: false},
		{line: "password rotation policy for shell scripts", want: false},
	}
	for _, tc := range cases {
		got := passwordArchivePattern.MatchString(tc.line)
		if got != tc.want {
			t.Fatalf("passwordArchivePattern.MatchString(%q) = %v, want %v", tc.line, got, tc.want)
		}
	}
}
