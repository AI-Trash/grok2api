package account

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/infra/persistence/relational"
	"github.com/chenyme/grok2api/backend/internal/infra/provider"
	cliprovider "github.com/chenyme/grok2api/backend/internal/infra/provider/cli"
	"github.com/chenyme/grok2api/backend/internal/infra/security"
	"github.com/chenyme/grok2api/backend/internal/repository"
)

func TestListAndDeleteBotFlaggedAccounts(t *testing.T) {
	ctx := context.Background()
	database, err := relational.OpenSQLite(ctx, filepath.Join(t.TempDir(), "bot-flag.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.InitializeSchema(ctx); err != nil {
		t.Fatal(err)
	}
	cipher, err := security.NewCipher(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	encrypt := func(value string) string {
		encrypted, encryptErr := cipher.Encrypt(value)
		if encryptErr != nil {
			t.Fatal(encryptErr)
		}
		return encrypted
	}
	encodeJWT := func(claims map[string]any) string {
		payload, marshalErr := json.Marshal(claims)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		return "hdr." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
	}
	repo := relational.NewAccountRepository(database)
	audits := relational.NewAuditRepository(database)
	bot, _, err := repo.UpsertByIdentity(ctx, accountdomain.Credential{
		Provider: accountdomain.ProviderBuild, Name: "bot", UserID: "bot-1", SourceKey: "bot-1",
		EncryptedAccessToken: encrypt(encodeJWT(map[string]any{"bot_flag_source": 1, "sub": "bot-1"})),
		EncryptedRefreshToken: encrypt("refresh-bot"), ExpiresAt: time.Now().UTC().Add(time.Hour),
		Enabled: true, AuthStatus: accountdomain.AuthStatusActive, Priority: 1, MaxConcurrent: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.UpsertByIdentity(ctx, accountdomain.Credential{
		Provider: accountdomain.ProviderBuild, Name: "human", UserID: "human-1", SourceKey: "human-1",
		EncryptedAccessToken: encrypt(encodeJWT(map[string]any{"sub": "human-1"})),
		EncryptedRefreshToken: encrypt("refresh-human"), ExpiresAt: time.Now().UTC().Add(time.Hour),
		Enabled: true, AuthStatus: accountdomain.AuthStatusActive, Priority: 1, MaxConcurrent: 8,
	}); err != nil {
		t.Fatal(err)
	}
	service := NewService(repo, audits, nil, stickySessionStub{}, provider.NewRegistry(cliprovider.NewAdapter(cliprovider.Config{}, cipher)), cipher, nil)

	marked, total, err := service.List(ctx, 1, 20, "", ListFilter{Provider: string(accountdomain.ProviderBuild), BotFlag: "marked"})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(marked) != 1 || marked[0].Credential.ID != bot.ID || marked[0].BotFlag == nil || *marked[0].BotFlag != "1" {
		t.Fatalf("marked list = total=%d items=%#v", total, marked)
	}
	unmarked, total, err := service.List(ctx, 1, 20, "", ListFilter{Provider: string(accountdomain.ProviderBuild), BotFlag: "unmarked"})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(unmarked) != 1 || unmarked[0].Credential.Name != "human" {
		t.Fatalf("unmarked list = total=%d items=%#v", total, unmarked)
	}

	deleted, err := service.DeleteBotFlaggedAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Fatalf("deleted = %d", deleted)
	}
	if _, err := repo.Get(ctx, bot.ID); err != repository.ErrNotFound {
		t.Fatalf("bot account still exists: %v", err)
	}
	remaining, total, err := service.List(ctx, 1, 20, "", ListFilter{Provider: string(accountdomain.ProviderBuild)})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(remaining) != 1 || remaining[0].Credential.Name != "human" {
		t.Fatalf("remaining after delete = total=%d items=%#v", total, remaining)
	}
}

type stickySessionStub struct{}

func (stickySessionStub) Get(context.Context, string, time.Time) (uint64, bool, error) {
	return 0, false, nil
}
func (stickySessionStub) Bind(context.Context, string, uint64, time.Time, time.Time) (uint64, error) {
	return 0, nil
}
func (stickySessionStub) Set(context.Context, string, uint64, time.Time) error { return nil }
func (stickySessionStub) DeleteByAccount(context.Context, uint64) error       { return nil }
