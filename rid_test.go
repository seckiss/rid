package rid

import (
	"regexp"
	"testing"
)

func Test_rid16(t *testing.T) {
	var uid16a = NewRID16()
	var uid16b = NewRID16()
	var pat = regexp.MustCompile(`^[a-zA-Z0-9]{16}$`)
	if !pat.MatchString(uid16a) || !pat.MatchString(uid16b) {
		t.Fatalf("uid16 not matching pattern: %s, %s\n", uid16a, uid16b)
	}
	if uid16a == uid16b {
		t.Fatalf("uid16a should be different from uid16b")
	}
}

func Test_rid20(t *testing.T) {
	var uid20a = NewRID20()
	var uid20b = NewRID20()
	var pat = regexp.MustCompile(`^[a-zA-Z0-9]{20}$`)
	if !pat.MatchString(uid20a) || !pat.MatchString(uid20b) {
		t.Fatalf("uid20 not matching pattern: %s, %s\n", uid20a, uid20b)
	}
	if uid20a == uid20b {
		t.Fatalf("uid20a should be different from uid20b")
	}
}
