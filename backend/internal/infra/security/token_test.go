package security

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestJWTPayloadHasClaim(t *testing.T) {
	encode := func(claims map[string]any) string {
		payload, err := json.Marshal(claims)
		if err != nil {
			t.Fatal(err)
		}
		return "hdr." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
	}

	present, ok := JWTPayloadHasClaim(encode(map[string]any{"bot_flag_source": "manual", "sub": "user-1"}), "bot_flag_source")
	if !ok || !present {
		t.Fatalf("expected present claim, ok=%v present=%v", ok, present)
	}

	present, ok = JWTPayloadHasClaim(encode(map[string]any{"sub": "user-1", "bot_flag_source": nil}), "bot_flag_source")
	if !ok || !present {
		t.Fatalf("nil claim value should still count as present, ok=%v present=%v", ok, present)
	}

	present, ok = JWTPayloadHasClaim(encode(map[string]any{"sub": "user-1"}), "bot_flag_source")
	if !ok || present {
		t.Fatalf("expected missing claim, ok=%v present=%v", ok, present)
	}

	if present, ok := JWTPayloadHasClaim("not-a-jwt", "bot_flag_source"); ok || present {
		t.Fatalf("invalid jwt should fail, ok=%v present=%v", ok, present)
	}
	if present, ok := JWTPayloadHasClaim("", "bot_flag_source"); ok || present {
		t.Fatalf("empty token should fail, ok=%v present=%v", ok, present)
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
