package cfg

import (
	"strings"
	"testing"
)

func TestValidate_TTL(t *testing.T) {
	cases := []struct {
		name          string
		interval      int
		batchSize     int
		batchPauseMS  int
		errorContains string
	}{
		{"defaults are valid", 60, 500, 100, ""},
		{"zero interval defaulted", 0, 500, 100, ""},
		{"zero batch defaulted", 60, 0, 100, ""},
		{"negative interval rejected", -1, 500, 100, "ttl.sweep_interval_seconds"},
		{"negative batch rejected", 60, -1, 100, "ttl.batch_size"},
		{"negative pause rejected", 60, 500, -1, "ttl.batch_pause_ms"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			original := Config
			t.Cleanup(func() { Config = original })
			copy_ := *Config
			Config = &copy_
			Config.TTL.SweepIntervalSeconds = tc.interval
			Config.TTL.BatchSize = tc.batchSize
			Config.TTL.BatchPauseMS = tc.batchPauseMS

			err := Validate()
			if tc.errorContains == "" {
				if err != nil {
					t.Fatalf("expected valid, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.errorContains) {
				t.Fatalf("expected error containing %q, got %v", tc.errorContains, err)
			}
		})
	}
}
