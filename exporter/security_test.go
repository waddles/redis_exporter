package exporter

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestShouldRedactConfigKey(t *testing.T) {
	for _, tst := range []struct {
		name          string
		key           string
		redactEnabled bool
		want          bool
	}{
		// Credentials are always redacted, regardless of the flag.
		{name: "requirepass redaction on", key: "requirepass", redactEnabled: true, want: true},
		{name: "requirepass redaction off", key: "requirepass", redactEnabled: false, want: true},
		{name: "masterauth redaction off", key: "masterauth", redactEnabled: false, want: true},
		{name: "tls-key-file-pass redaction off", key: "tls-key-file-pass", redactEnabled: false, want: true},
		{name: "tls-client-key-file-pass redaction off", key: "tls-client-key-file-pass", redactEnabled: false, want: true},

		// Defense-in-depth substring backstop, regardless of the flag.
		{name: "unknown password key redaction off", key: "some-new-password", redactEnabled: false, want: true},
		{name: "unknown passwd key redaction off", key: "announce-auth-passwd", redactEnabled: false, want: true},
		{name: "unknown secret key redaction off", key: "module-shared-secret", redactEnabled: false, want: true},
		{name: "unknown token key redaction off", key: "auth-token", redactEnabled: false, want: true},

		// Keys are normalized before lookup so a fork returning a different
		// casing or surrounding whitespace cannot bypass redaction.
		{name: "mixed case credential", key: "RequirePass", redactEnabled: false, want: true},
		{name: "padded credential", key: "  requirepass  ", redactEnabled: false, want: true},

		// Optional sensitive keys depend on the flag.
		{name: "user redaction on", key: "user", redactEnabled: true, want: true},
		{name: "user redaction off", key: "user", redactEnabled: false, want: false},
		{name: "masteruser redaction on", key: "masteruser", redactEnabled: true, want: true},
		{name: "masteruser redaction off", key: "masteruser", redactEnabled: false, want: false},

		// Non-sensitive keys are never redacted.
		{name: "appendonly redaction on", key: "appendonly", redactEnabled: true, want: false},
		{name: "maxmemory redaction off", key: "maxmemory", redactEnabled: false, want: false},
	} {
		t.Run(tst.name, func(t *testing.T) {
			if got := shouldRedactConfigKey(tst.key, tst.redactEnabled); got != tst.want {
				t.Errorf("shouldRedactConfigKey(%q, %v) = %v, want %v", tst.key, tst.redactEnabled, got, tst.want)
			}
		})
	}
}

// collectConfigKeyValues runs extractConfigMetrics over the given config and
// returns a key -> value map built from the exported config_key_value metrics.
func collectConfigKeyValues(t *testing.T, redactEnabled bool, config map[string]string) map[string]string {
	t.Helper()

	e, err := NewRedisExporter("redis://localhost:6379", Options{
		InclConfigMetrics:   true,
		RedactConfigMetrics: redactEnabled,
		Namespace:           "test",
	})
	if err != nil {
		t.Fatalf("NewRedisExporter() failed: %v", err)
	}

	ch := make(chan prometheus.Metric, len(config)*2+8)
	if _, err := e.extractConfigMetrics(ch, config); err != nil {
		t.Fatalf("extractConfigMetrics() failed: %v", err)
	}
	close(ch)

	exported := make(map[string]string)
	for m := range ch {
		metricDto := &dto.Metric{}
		if err := m.Write(metricDto); err != nil {
			t.Fatalf("metric.Write() failed: %v", err)
		}

		var key, value string
		hasKey, hasValue := false, false
		for _, lp := range metricDto.Label {
			switch lp.GetName() {
			case "key":
				key, hasKey = lp.GetValue(), true
			case "value":
				value, hasValue = lp.GetValue(), true
			}
		}
		if hasKey && hasValue {
			exported[key] = value
		}
	}
	return exported
}

func TestExtractConfigMetricsRedaction(t *testing.T) {
	const (
		password = "very-secret-password"
		username = "redis-user"
	)

	config := map[string]string{
		"requirepass": password,
		"masterauth":  password,
		"user":        username,
		"masteruser":  username,
		"appendonly":  "no",
		"databases":   "16",
	}

	for _, tst := range []struct {
		name             string
		redactEnabled    bool
		wantExportedKeys map[string]string // keys that must be present with the given value
		wantWithheldKeys []string          // keys that must not be present at all
	}{
		{
			name:          "redaction enabled (default)",
			redactEnabled: true,
			wantExportedKeys: map[string]string{
				"appendonly": "no",
				"databases":  "16",
			},
			wantWithheldKeys: []string{"requirepass", "masterauth", "user", "masteruser"},
		},
		{
			name:          "redaction disabled (authorized debugging)",
			redactEnabled: false,
			wantExportedKeys: map[string]string{
				"appendonly": "no",
				"databases":  "16",
				"user":       username, // usernames are revealed for debugging
				"masteruser": username,
			},
			wantWithheldKeys: []string{"requirepass", "masterauth"}, // credentials stay secret
		},
	} {
		t.Run(tst.name, func(t *testing.T) {
			exported := collectConfigKeyValues(t, tst.redactEnabled, config)

			// Credentials must never appear with their real value.
			for key, val := range exported {
				if val == password {
					t.Errorf("SECURITY FAILURE: credential exposed in config_key_value{key=%q}", key)
				}
			}

			for key, want := range tst.wantExportedKeys {
				got, ok := exported[key]
				if !ok {
					t.Errorf("expected config_key_value{key=%q} to be exported, but it was not", key)
					continue
				}
				if got != want {
					t.Errorf("config_key_value{key=%q} = %q, want %q", key, got, want)
				}
			}

			for _, key := range tst.wantWithheldKeys {
				if _, ok := exported[key]; ok {
					t.Errorf("expected config_key_value{key=%q} to be withheld, but it was exported", key)
				}
			}
		})
	}
}
