package security

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestJWTPayloadClaim(t *testing.T) {
	encode := func(claims map[string]any) string {
		payload, err := json.Marshal(claims)
		if err != nil {
			t.Fatal(err)
		}
		return "hdr." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
	}

	// bot_flag_source 已知可能值为数字 1。
	value, found, ok := JWTPayloadClaim(encode(map[string]any{"bot_flag_source": 1, "sub": "user-1"}), "bot_flag_source")
	if !ok || !found || value != "1" {
		t.Fatalf("numeric claim = %q found=%v ok=%v", value, found, ok)
	}

	value, found, ok = JWTPayloadClaim(encode(map[string]any{"bot_flag_source": "1", "sub": "user-1"}), "bot_flag_source")
	if !ok || !found || value != "1" {
		t.Fatalf("string claim = %q found=%v ok=%v", value, found, ok)
	}

	value, found, ok = JWTPayloadClaim(encode(map[string]any{"sub": "user-1", "bot_flag_source": nil}), "bot_flag_source")
	if !ok || !found || value != "" {
		t.Fatalf("null claim = %q found=%v ok=%v", value, found, ok)
	}

	value, found, ok = JWTPayloadClaim(encode(map[string]any{"bot_flag_source": true}), "bot_flag_source")
	if !ok || !found || value != "true" {
		t.Fatalf("bool claim = %q found=%v ok=%v", value, found, ok)
	}

	value, found, ok = JWTPayloadClaim(encode(map[string]any{"sub": "user-1"}), "bot_flag_source")
	if !ok || found || value != "" {
		t.Fatalf("missing claim = %q found=%v ok=%v", value, found, ok)
	}

	if value, found, ok := JWTPayloadClaim("not-a-jwt", "bot_flag_source"); ok || found || value != "" {
		t.Fatalf("invalid jwt should fail, value=%q found=%v ok=%v", value, found, ok)
	}
	if value, found, ok := JWTPayloadClaim("", "bot_flag_source"); ok || found || value != "" {
		t.Fatalf("empty token should fail, value=%q found=%v ok=%v", value, found, ok)
	}
}

func TestClientKeyFormat(t *testing.T) {
	raw := FormatClientKey("abc123", "secret_value")
	if raw != "g2a_abc123_secret_value" {
		t.Fatalf("formatted key = %q", raw)
	}
	prefix, ok := SplitClientKey(raw)
	if !ok || prefix != "abc123" {
		t.Fatalf("SplitClientKey(%q) = %q, %v", raw, prefix, ok)
	}
	for _, value := range []string{"", "g2a_", "g2a__secret", "other_abc123_secret", "gbp_abc123_old_secret"} {
		if _, ok := SplitClientKey(value); ok {
			t.Fatalf("SplitClientKey(%q) unexpectedly succeeded", value)
		}
	}
}
