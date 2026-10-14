package ttlmarker

import "testing"

func TestEncodeDecodeRoundTrip(t *testing.T) {
	createSQL := "CREATE TABLE `sessions` (`id` INTEGER PRIMARY KEY, `expires_at` INTEGER NOT NULL)" + Encode("expires_at")
	col, ok := Decode(createSQL)
	if !ok || col != "expires_at" {
		t.Fatalf("Decode() = %q, %v, want %q, true", col, ok, "expires_at")
	}
}

func TestEncodeRejectsUnsafeIdentifiers(t *testing.T) {
	for _, name := range []string{"", "a b", "a*/", "1a", "a/b", "a,b"} {
		if got := Encode(name); got != "" {
			t.Errorf("Encode(%q) = %q, want empty", name, got)
		}
	}
	for _, name := range []string{"a", "_a", "A1", "expires_at", "ttl$col"} {
		if got := Encode(name); got == "" {
			t.Errorf("Encode(%q) = empty, want marker", name)
		}
	}
}

func TestDecodeIgnoresMarkerInsideQuotedText(t *testing.T) {
	// A marker that appears inside a DEFAULT string is data, not a marker.
	createSQL := "CREATE TABLE t (c TEXT DEFAULT '" + markerOpen + "evil*/' )"
	if _, ok := Decode(createSQL); ok {
		t.Fatal("Decode picked up a marker inside a quoted string")
	}
}

func TestDecodeAbsent(t *testing.T) {
	if col, ok := Decode("CREATE TABLE t (id INTEGER PRIMARY KEY)"); ok {
		t.Fatalf("Decode() = %q, true, want no marker", col)
	}
}

func TestExtractDirective(t *testing.T) {
	cases := []struct {
		comment string
		col     string
		ok      bool
	}{
		{"marmot:ttl=expires_at", "expires_at", true},
		{"Session store; MARMOT:TTL=expireAt", "expireAt", true},
		{"plain comment", "", false},
		{"marmot:ttl=1bad", "", false},
		{"marmot:ttl=", "", false},
	}
	for _, tc := range cases {
		col, ok := ExtractDirective(tc.comment)
		if ok != tc.ok || col != tc.col {
			t.Errorf("ExtractDirective(%q) = %q, %v, want %q, %v", tc.comment, col, ok, tc.col, tc.ok)
		}
	}
}
