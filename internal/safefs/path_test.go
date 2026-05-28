package safefs

import "testing"

func TestHasWindowsDrivePathPrefix(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{path: "", want: false},
		{path: "C", want: false},
		{path: "C:", want: true},
		{path: "C:/absolute", want: true},
		{path: "c:relative", want: true},
		{path: "1:/not-drive", want: false},
		{path: "/C:/not-prefix", want: false},
		{path: "skills/C:/nested", want: false},
	}
	for _, tc := range tests {
		if got := HasWindowsDrivePathPrefix(tc.path); got != tc.want {
			t.Fatalf("HasWindowsDrivePathPrefix(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
