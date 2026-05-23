package app

import "testing"

func TestNormalizeJSONErrorCode(t *testing.T) {
	tests := []struct {
		name     string
		code     string
		fallback string
		want     string
	}{
		{
			name:     "keeps valid code",
			code:     "FETCH_COPY_FAILED",
			fallback: "FETCH_FAILED",
			want:     "FETCH_COPY_FAILED",
		},
		{
			name:     "uses fallback for invalid code",
			code:     "bad-code",
			fallback: "FETCH_FAILED",
			want:     "FETCH_FAILED",
		},
		{
			name:     "uses fallback for empty code",
			code:     "",
			fallback: "INSTALL_FAILED",
			want:     "INSTALL_FAILED",
		},
		{
			name:     "uses unknown when code and fallback invalid",
			code:     "bad-code",
			fallback: "bad-fallback",
			want:     "UNKNOWN_ERROR",
		},
		{
			name:     "trims and accepts spaced valid code",
			code:     "  UPDATE_FAILED  ",
			fallback: "UNKNOWN_ERROR",
			want:     "UPDATE_FAILED",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeJSONErrorCode(tc.code, tc.fallback)
			if got != tc.want {
				t.Fatalf("normalizeJSONErrorCode(%q, %q) = %q, want %q", tc.code, tc.fallback, got, tc.want)
			}
		})
	}
}
