package exitcode

import "testing"

func TestCodeInt(t *testing.T) {
	cases := map[Code]int{
		OK:       0,
		Error:    1,
		Rejected: 2,
	}
	for code, want := range cases {
		if got := code.Int(); got != want {
			t.Fatalf("%v.Int() = %d, want %d", code, got, want)
		}
	}
}
