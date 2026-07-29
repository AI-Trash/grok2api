package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const clientKeyScheme = "g2a"

type adminClaims struct {
	AdminID   uint64 `json:"adminId"`
	SessionID uint64 `json:"sessionId"`
	jwt.RegisteredClaims
}

type AdminTokenIdentity struct {
	AdminID   uint64
	SessionID uint64
}

// TokenService 负责管理员 access token 和随机 refresh token。
type TokenService struct {
	secret []byte
	issuer string
}

func NewTokenService(secret string) *TokenService {
	return &TokenService{secret: []byte(secret), issuer: "grok2api"}
}

// CreateAccessToken 创建短期管理员 JWT。
func (s *TokenService) CreateAccessToken(adminID, sessionID uint64, ttl time.Duration) (string, time.Time, error) {
	now := time.Now().UTC()
	expiresAt := now.Add(ttl)
	claims := adminClaims{
		AdminID: adminID, SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   fmt.Sprintf("%d", adminID),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(s.secret)
	return signed, expiresAt, err
}

// ParseAccessToken 校验管理员 JWT 并返回管理员 ID。
func (s *TokenService) ParseAccessToken(raw string) (AdminTokenIdentity, error) {
	claims := &adminClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("不支持的 JWT 签名算法")
		}
		return s.secret, nil
	}, jwt.WithIssuer(s.issuer))
	if err != nil || !token.Valid || claims.AdminID == 0 || claims.SessionID == 0 {
		return AdminTokenIdentity{}, fmt.Errorf("管理员令牌无效")
	}
	return AdminTokenIdentity{AdminID: claims.AdminID, SessionID: claims.SessionID}, nil
}

// NewOpaqueToken 创建不可预测的 refresh token 或客户端 Key 密钥段。
func NewOpaqueToken(bytesLength int) (string, error) {
	buf := make([]byte, bytesLength)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// NewHexToken 创建只包含十六进制字符的随机标识，适合放在分隔格式中。
func NewHexToken(bytesLength int) (string, error) {
	buf := make([]byte, bytesLength)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// HashToken 返回不可逆的 SHA-256 十六进制摘要。
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// JWTPayloadClaim 在不校验签名的情况下解析 JWT payload，读取指定 claim 的展示值。
// ok=false 表示输入不是可解码的 JWT；found 表示 claim 键存在；value 为字符串化后的 claim 值。
// null claim 返回 found=true 且 value 为空字符串。
func JWTPayloadClaim(raw, claim string) (value string, found bool, ok bool) {
	raw = strings.TrimSpace(raw)
	claim = strings.TrimSpace(claim)
	if raw == "" || claim == "" {
		return "", false, false
	}
	parts := strings.Split(raw, ".")
	if len(parts) < 2 || parts[1] == "" {
		return "", false, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return "", false, false
		}
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", false, false
	}
	rawValue, found := claims[claim]
	if !found {
		return "", false, true
	}
	return formatJWTClaimValue(rawValue), true, true
}

func formatJWTClaimValue(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	// bot_flag_source 等 claim 的已知形态为数字（例如 1、2），优先按 number 解析，避免被其它类型误读。
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var asNumber json.Number
	if err := decoder.Decode(&asNumber); err == nil {
		return asNumber.String()
	}
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		return asString
	}
	var asBool bool
	if err := json.Unmarshal(raw, &asBool); err == nil {
		if asBool {
			return "true"
		}
		return "false"
	}
	return strings.TrimSpace(string(raw))
}

// FormatClientKey 生成 g2a_<prefix>_<secret> 格式的客户端 Key。
func FormatClientKey(prefix, secret string) string {
	return clientKeyScheme + "_" + prefix + "_" + secret
}

// SplitClientKey 解析 g2a_<prefix>_<secret> 格式的客户端 Key。
func SplitClientKey(raw string) (string, bool) {
	parts := strings.SplitN(raw, "_", 3)
	if len(parts) != 3 || parts[0] != clientKeyScheme || parts[1] == "" || parts[2] == "" {
		return "", false
	}
	return parts[1], true
}
