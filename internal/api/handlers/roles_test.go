package handlers_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/nexspence-oss/nexspence/internal/api/handlers"
	"github.com/nexspence-oss/nexspence/internal/domain"
	"github.com/nexspence-oss/nexspence/internal/testutil"
)

func mountRoles(t *testing.T) (*gin.Engine, *testutil.RoleRepo, *testutil.UserRepo) {
	t.Helper()
	roles := testutil.NewRoleRepo()
	users := testutil.NewUserRepo()
	h := handlers.NewRoleHandler(roles, users)
	r := gin.New()
	r.GET("/service/rest/v1/security/roles", h.List)
	r.POST("/service/rest/v1/security/roles", h.Create)
	r.PUT("/service/rest/v1/security/roles/:id", h.Update)
	r.DELETE("/service/rest/v1/security/roles/:id", h.Delete)
	r.PUT("/service/rest/v1/security/users/:userId/roles", h.SetUserRoles)
	return r, roles, users
}

func TestRoleHandler_List_Empty(t *testing.T) {
	r, _, _ := mountRoles(t)
	rec := do(t, r, http.MethodGet, "/service/rest/v1/security/roles", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var got []domain.Role
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	assert.Empty(t, got)
}

func TestRoleHandler_Create_Then_List(t *testing.T) {
	r, _, _ := mountRoles(t)
	rec := do(t, r, http.MethodPost, "/service/rest/v1/security/roles",
		map[string]any{"name": "dev", "description": "developers"})
	require.Equal(t, http.StatusCreated, rec.Code)
	var created domain.Role
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	assert.Equal(t, "dev", created.Name)
	assert.Equal(t, "default", created.Source)

	rec = do(t, r, http.MethodGet, "/service/rest/v1/security/roles", nil)
	var got []domain.Role
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Len(t, got, 1)
}

func TestRoleHandler_Create_BadJSON_400(t *testing.T) {
	r, _, _ := mountRoles(t)
	rec := doRaw(t, r, http.MethodPost, "/service/rest/v1/security/roles", []byte(`{not json`))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestRoleHandler_Create_EmptyName_400(t *testing.T) {
	r, _, _ := mountRoles(t)
	rec := do(t, r, http.MethodPost, "/service/rest/v1/security/roles",
		map[string]any{"description": "no name"})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestRoleHandler_Update(t *testing.T) {
	r, roles, _ := mountRoles(t)
	ro := &domain.Role{Name: "ops"}
	require.NoError(t, roles.Create(testContext(), ro))
	rec := do(t, r, http.MethodPut, "/service/rest/v1/security/roles/"+ro.ID,
		map[string]any{"name": "ops2", "description": "renamed"})
	assert.Equal(t, http.StatusOK, rec.Code)
}

// A body without "privileges" (a rename from a client that edits only name
// and description) must leave the role's privileges alone instead of
// emptying them; an explicit list, empty included, still replaces them.
func TestRoleHandler_Update_WithoutPrivileges_KeepsThem(t *testing.T) {
	r, roles, _ := mountRoles(t)
	ro := &domain.Role{Name: "ops"}
	require.NoError(t, roles.Create(testContext(), ro))
	require.NoError(t, roles.SetPrivileges(testContext(), ro.ID, []string{"p1", "p2"}))

	rec := do(t, r, http.MethodPut, "/service/rest/v1/security/roles/"+ro.ID,
		map[string]any{"name": "ops2", "description": "renamed"})
	require.Equal(t, http.StatusOK, rec.Code)
	assert.ElementsMatch(t, []string{"p1", "p2"}, roles.PrivilegesOf(ro.ID))
	var got domain.Role
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	assert.ElementsMatch(t, []string{"p1", "p2"}, got.Privileges)

	rec = do(t, r, http.MethodPut, "/service/rest/v1/security/roles/"+ro.ID,
		map[string]any{"name": "ops2", "privileges": []string{}})
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, roles.PrivilegesOf(ro.ID))
}

func TestRoleHandler_Delete(t *testing.T) {
	r, roles, _ := mountRoles(t)
	ro := &domain.Role{Name: "temp"}
	require.NoError(t, roles.Create(testContext(), ro))
	rec := do(t, r, http.MethodDelete, "/service/rest/v1/security/roles/"+ro.ID, nil)
	assert.Equal(t, http.StatusNoContent, rec.Code)
}

func TestRoleHandler_SetUserRoles_UserNotFound_404(t *testing.T) {
	r, _, _ := mountRoles(t)
	rec := do(t, r, http.MethodPut, "/service/rest/v1/security/users/ghost/roles",
		map[string]any{"roleIds": []string{"r1"}})
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestRoleHandler_SetUserRoles_OK(t *testing.T) {
	r, _, users := mountRoles(t)
	u := &domain.User{Username: "alice", Email: "alice@test.com"}
	require.NoError(t, users.Create(testContext(), u))
	rec := do(t, r, http.MethodPut, "/service/rest/v1/security/users/alice/roles",
		map[string]any{"roleIds": []string{"r1", "r2"}})
	assert.Equal(t, http.StatusNoContent, rec.Code)
}

func TestRoleHandler_Update_BadJSON_400(t *testing.T) {
	r, _, _ := mountRoles(t)
	rec := doRaw(t, r, http.MethodPut, "/service/rest/v1/security/roles/any-id", []byte(`{bad`))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestRoleHandler_SetUserRoles_BadJSON_400(t *testing.T) {
	r, _, _ := mountRoles(t)
	rec := doRaw(t, r, http.MethodPut, "/service/rest/v1/security/users/someone/roles", []byte(`{bad`))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ── 500-branch tests ──────────────────────────────────────────────────────────

func TestRoleHandler_List_RepoError_500(t *testing.T) {
	r, roles, _ := mountRoles(t)
	roles.Err = errors.New("db down")
	rec := do(t, r, http.MethodGet, "/service/rest/v1/security/roles", nil)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestRoleHandler_Create_RepoError_500(t *testing.T) {
	r, roles, _ := mountRoles(t)
	roles.Err = errors.New("db down")
	rec := do(t, r, http.MethodPost, "/service/rest/v1/security/roles",
		map[string]any{"name": "fail"})
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestRoleHandler_Create_SetPrivileges_RepoError_500(t *testing.T) {
	// Create succeeds but SetPrivileges fails — exercises the SetPrivileges 500 branch.
	r, roles, _ := mountRoles(t)
	roles.SetPrivilegesErr = errors.New("privilege store down")
	rec := do(t, r, http.MethodPost, "/service/rest/v1/security/roles",
		map[string]any{"name": "withpriv", "privileges": []string{"p1"}})
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestRoleHandler_Update_RepoError_500(t *testing.T) {
	r, roles, _ := mountRoles(t)
	roles.Err = errors.New("db down")
	rec := do(t, r, http.MethodPut, "/service/rest/v1/security/roles/any-id",
		map[string]any{"name": "ops2"})
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestRoleHandler_Update_SetPrivileges_RepoError_500(t *testing.T) {
	// Update succeeds but SetPrivileges fails — exercises the second 500 branch in Update.
	r, roles, _ := mountRoles(t)
	roles.SetPrivilegesErr = errors.New("privilege store down")
	rec := do(t, r, http.MethodPut, "/service/rest/v1/security/roles/any-id",
		map[string]any{"name": "ops2", "privileges": []string{"p1"}})
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestRoleHandler_Delete_RepoError_500(t *testing.T) {
	r, roles, _ := mountRoles(t)
	roles.Err = errors.New("db down")
	rec := do(t, r, http.MethodDelete, "/service/rest/v1/security/roles/any-id", nil)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestRoleHandler_SetUserRoles_RepoError_500(t *testing.T) {
	// Seed a user so the 404 guard passes, then set roles.Err so SetUserRoles fails.
	_, roles, users := mountRoles(t)
	u := &domain.User{Username: "bob", Email: "bob@test.com"}
	require.NoError(t, users.Create(testContext(), u))
	roles.Err = errors.New("db down")

	// Remount so the handler uses the same (now-errored) roles mock.
	h := handlers.NewRoleHandler(roles, users)
	r2 := gin.New()
	r2.PUT("/service/rest/v1/security/users/:userId/roles", h.SetUserRoles)

	rec := do(t, r2, http.MethodPut, "/service/rest/v1/security/users/bob/roles",
		map[string]any{"roleIds": []string{"r1"}})
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ── JWT revocation on role changes ────────────────────────────────────────────
//
// A JWT carries the role names it was issued with, so every change to who
// holds which role name must move the affected users' tokens_valid_after.

// bumpFailingUsers fails only BumpTokensValidAfter; Get keeps working so the
// role change itself goes through.
type bumpFailingUsers struct{ *testutil.UserRepo }

func (bumpFailingUsers) BumpTokensValidAfter(context.Context, string) error {
	return errors.New("db down")
}

// seedUser creates a user whose revocation cutoff starts at zero.
func seedUser(t *testing.T, users *testutil.UserRepo, username string) *domain.User {
	t.Helper()
	u := &domain.User{Username: username, Email: username + "@test.com"}
	require.NoError(t, users.Create(testContext(), u))
	return u
}

// seedRoleWithMembers creates a role and assigns it to the given users.
func seedRoleWithMembers(t *testing.T, roles *testutil.RoleRepo, name string, members ...*domain.User) *domain.Role {
	t.Helper()
	ro := &domain.Role{Name: name}
	require.NoError(t, roles.Create(testContext(), ro))
	for _, u := range members {
		require.NoError(t, roles.SetUserRoles(testContext(), u.ID, []string{ro.ID}))
	}
	return ro
}

func cutoffOf(t *testing.T, users *testutil.UserRepo, id string) time.Time {
	t.Helper()
	u, err := users.GetByID(testContext(), id)
	require.NoError(t, err)
	return u.TokensValidAfter
}

func assertRevokedSince(t *testing.T, users *testutil.UserRepo, since time.Time, us ...*domain.User) {
	t.Helper()
	for _, u := range us {
		cut := cutoffOf(t, users, u.ID)
		assert.False(t, cut.IsZero(), "%s: tokens_valid_after not bumped", u.Username)
		assert.False(t, cut.Before(since), "%s: tokens_valid_after %v predates the change", u.Username, cut)
	}
}

func assertNotRevoked(t *testing.T, users *testutil.UserRepo, us ...*domain.User) {
	t.Helper()
	for _, u := range us {
		assert.True(t, cutoffOf(t, users, u.ID).IsZero(), "%s: tokens_valid_after bumped", u.Username)
	}
}

func TestRoleHandler_SetUserRoles_BumpsTokensValidAfter(t *testing.T) {
	r, roles, users := mountRoles(t)
	alice := seedUser(t, users, "alice")
	before := time.Now()
	rec := do(t, r, http.MethodPut, "/service/rest/v1/security/users/alice/roles",
		map[string]any{"roleIds": []string{}})
	require.Equal(t, http.StatusNoContent, rec.Code)
	assert.Empty(t, rec.Body.String())
	assert.Empty(t, roles.UserRoleIDs(alice.ID))
	assertRevokedSince(t, users, before, alice)
}

// Re-sending the role set a user already has still revokes: the handler does
// not compare sets.
func TestRoleHandler_SetUserRoles_SameSet_Bumps(t *testing.T) {
	r, roles, users := mountRoles(t)
	alice := seedUser(t, users, "alice")
	require.NoError(t, roles.SetUserRoles(testContext(), alice.ID, []string{"r1"}))
	before := time.Now()
	rec := do(t, r, http.MethodPut, "/service/rest/v1/security/users/alice/roles",
		map[string]any{"roleIds": []string{"r1"}})
	require.Equal(t, http.StatusNoContent, rec.Code)
	assertRevokedSince(t, users, before, alice)
}

func TestRoleHandler_SetUserRoles_OtherUsersNotBumped(t *testing.T) {
	r, _, users := mountRoles(t)
	seedUser(t, users, "alice")
	bob := seedUser(t, users, "bob")
	rec := do(t, r, http.MethodPut, "/service/rest/v1/security/users/alice/roles",
		map[string]any{"roleIds": []string{"r1"}})
	require.Equal(t, http.StatusNoContent, rec.Code)
	assertNotRevoked(t, users, bob)
}

func TestRoleHandler_SetUserRoles_NotFound_NoBump(t *testing.T) {
	r, _, users := mountRoles(t)
	bob := seedUser(t, users, "bob")
	rec := do(t, r, http.MethodPut, "/service/rest/v1/security/users/ghost/roles",
		map[string]any{"roleIds": []string{"r1"}})
	require.Equal(t, http.StatusNotFound, rec.Code)
	assert.JSONEq(t, `{"error":"user not found: ghost"}`, rec.Body.String())
	assertNotRevoked(t, users, bob)
}

func TestRoleHandler_SetUserRoles_BadJSON_NoBump(t *testing.T) {
	r, roles, users := mountRoles(t)
	alice := seedUser(t, users, "alice")
	rec := doRaw(t, r, http.MethodPut, "/service/rest/v1/security/users/alice/roles", []byte(`{`))
	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Empty(t, roles.UserRoleIDs(alice.ID))
	assertNotRevoked(t, users, alice)
}

func TestRoleHandler_SetUserRoles_RepoError_NoBump(t *testing.T) {
	r, roles, users := mountRoles(t)
	alice := seedUser(t, users, "alice")
	roles.Err = errors.New("db down")
	rec := do(t, r, http.MethodPut, "/service/rest/v1/security/users/alice/roles",
		map[string]any{"roleIds": []string{"r1"}})
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	assertNotRevoked(t, users, alice)
}

// A failed bump does not undo the role change, which is already stored: the
// request still succeeds and the failure is logged, as for disable and
// password changes.
func TestRoleHandler_SetUserRoles_BumpFails_Still204(t *testing.T) {
	roles := testutil.NewRoleRepo()
	users := testutil.NewUserRepo()
	alice := seedUser(t, users, "alice")
	core, logs := observer.New(zapcore.DebugLevel)
	h := handlers.NewRoleHandler(roles, bumpFailingUsers{users}).WithLogger(zap.New(core).Sugar())
	r := gin.New()
	r.PUT("/service/rest/v1/security/users/:userId/roles", h.SetUserRoles)

	rec := do(t, r, http.MethodPut, "/service/rest/v1/security/users/alice/roles",
		map[string]any{"roleIds": []string{"r1", "r2"}})
	require.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, []string{"r1", "r2"}, roles.UserRoleIDs(alice.ID))

	entries := logs.FilterMessage("BumpTokensValidAfter failed after role change").All()
	require.Len(t, entries, 1)
	assert.Equal(t, zapcore.WarnLevel, entries[0].Level)
	assert.Equal(t, alice.ID, entries[0].ContextMap()["user"])
}

func TestRoleHandler_Delete_RevokesMembers(t *testing.T) {
	r, roles, users := mountRoles(t)
	alice, bob, carol := seedUser(t, users, "alice"), seedUser(t, users, "bob"), seedUser(t, users, "carol")
	ro := seedRoleWithMembers(t, roles, "ops", alice, bob)
	seedRoleWithMembers(t, roles, "dev", carol)
	before := time.Now()
	rec := do(t, r, http.MethodDelete, "/service/rest/v1/security/roles/"+ro.ID, nil)
	require.Equal(t, http.StatusNoContent, rec.Code)
	assertRevokedSince(t, users, before, alice, bob)
	assertNotRevoked(t, users, carol)
}

func TestRoleHandler_Delete_UnknownID_NoBump(t *testing.T) {
	r, roles, users := mountRoles(t)
	alice := seedUser(t, users, "alice")
	seedRoleWithMembers(t, roles, "ops", alice)
	rec := do(t, r, http.MethodDelete, "/service/rest/v1/security/roles/role-404", nil)
	require.Equal(t, http.StatusNoContent, rec.Code)
	assertNotRevoked(t, users, alice)
}

func TestRoleHandler_Delete_RepoError_NoBump(t *testing.T) {
	r, roles, users := mountRoles(t)
	alice := seedUser(t, users, "alice")
	ro := seedRoleWithMembers(t, roles, "ops", alice)
	roles.Err = errors.New("db down")
	rec := do(t, r, http.MethodDelete, "/service/rest/v1/security/roles/"+ro.ID, nil)
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	assertNotRevoked(t, users, alice)
}

func TestRoleHandler_Update_Rename_RevokesMembers(t *testing.T) {
	r, roles, users := mountRoles(t)
	alice, bob := seedUser(t, users, "alice"), seedUser(t, users, "bob")
	ro := seedRoleWithMembers(t, roles, "ops", alice)
	before := time.Now()
	rec := do(t, r, http.MethodPut, "/service/rest/v1/security/roles/"+ro.ID,
		map[string]any{"name": "ops2"})
	require.Equal(t, http.StatusOK, rec.Code)
	assertRevokedSince(t, users, before, alice)
	assertNotRevoked(t, users, bob)
}

func TestRoleHandler_Update_SameName_NoBump(t *testing.T) {
	r, roles, users := mountRoles(t)
	alice := seedUser(t, users, "alice")
	ro := seedRoleWithMembers(t, roles, "ops", alice)
	rec := do(t, r, http.MethodPut, "/service/rest/v1/security/roles/"+ro.ID,
		map[string]any{"name": "ops", "description": "only the description"})
	require.Equal(t, http.StatusOK, rec.Code)
	assertNotRevoked(t, users, alice)
}

// A body without "name" stores an empty name, which is a rename.
func TestRoleHandler_Update_EmptyName_Revokes(t *testing.T) {
	r, roles, users := mountRoles(t)
	alice := seedUser(t, users, "alice")
	ro := seedRoleWithMembers(t, roles, "ops", alice)
	before := time.Now()
	rec := do(t, r, http.MethodPut, "/service/rest/v1/security/roles/"+ro.ID,
		map[string]any{"description": "no name"})
	require.Equal(t, http.StatusOK, rec.Code)
	assertRevokedSince(t, users, before, alice)
}

func TestRoleHandler_Update_UnknownID_NoBump(t *testing.T) {
	r, roles, users := mountRoles(t)
	alice := seedUser(t, users, "alice")
	seedRoleWithMembers(t, roles, "ops", alice)
	rec := do(t, r, http.MethodPut, "/service/rest/v1/security/roles/role-404",
		map[string]any{"name": "ops2"})
	require.Equal(t, http.StatusOK, rec.Code)
	assertNotRevoked(t, users, alice)
}

func TestRoleHandler_Update_RepoError_NoBump(t *testing.T) {
	r, roles, users := mountRoles(t)
	alice := seedUser(t, users, "alice")
	ro := seedRoleWithMembers(t, roles, "ops", alice)
	roles.Err = errors.New("db down")
	rec := do(t, r, http.MethodPut, "/service/rest/v1/security/roles/"+ro.ID,
		map[string]any{"name": "ops2"})
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	assertNotRevoked(t, users, alice)
}

func TestRoleHandler_Update_Duplicate409_NoBump(t *testing.T) {
	r, roles, users := mountRoles(t)
	alice := seedUser(t, users, "alice")
	ro := seedRoleWithMembers(t, roles, "ops", alice)
	roles.Err = duplicateName
	rec := do(t, r, http.MethodPut, "/service/rest/v1/security/roles/"+ro.ID,
		map[string]any{"name": "dev"})
	assertNameConflict(t, rec.Code, rec.Body.Bytes())
	assertNotRevoked(t, users, alice)
}

// The rename is stored before the privileges step, so a failure there must
// not leave the members' old JWTs alive.
func TestRoleHandler_Update_Rename_SetPrivilegesError_StillRevokes(t *testing.T) {
	r, roles, users := mountRoles(t)
	alice := seedUser(t, users, "alice")
	ro := seedRoleWithMembers(t, roles, "ops", alice)
	roles.SetPrivilegesErr = errors.New("privilege store down")
	before := time.Now()
	rec := do(t, r, http.MethodPut, "/service/rest/v1/security/roles/"+ro.ID,
		map[string]any{"name": "ops2", "privileges": []string{"p1"}})
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	assertRevokedSince(t, users, before, alice)
}

// getFailingRoles fails only Get, with an error other than ErrNotFound.
type getFailingRoles struct{ *testutil.RoleRepo }

func (getFailingRoles) Get(context.Context, string) (*domain.Role, error) {
	return nil, errors.New("db down")
}

// memberListFailingRoles fails only ListMemberIDs.
type memberListFailingRoles struct{ *testutil.RoleRepo }

func (memberListFailingRoles) ListMemberIDs(context.Context, string) ([]string, error) {
	return nil, errors.New("db down")
}

// deleteFailingRoles fails only Delete; the members read before it works.
type deleteFailingRoles struct{ *testutil.RoleRepo }

func (deleteFailingRoles) Delete(context.Context, string) error {
	return errors.New("db down")
}

// The previous name cannot be read: answer 500 before touching the role.
func TestRoleHandler_Update_GetError_500_NoUpdate(t *testing.T) {
	roles := testutil.NewRoleRepo()
	users := testutil.NewUserRepo()
	alice := seedUser(t, users, "alice")
	ro := seedRoleWithMembers(t, roles, "ops", alice)
	h := handlers.NewRoleHandler(getFailingRoles{roles}, users)
	r := gin.New()
	r.PUT("/service/rest/v1/security/roles/:id", h.Update)

	rec := do(t, r, http.MethodPut, "/service/rest/v1/security/roles/"+ro.ID,
		map[string]any{"name": "ops2"})
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.JSONEq(t, `{"error":"db down"}`, rec.Body.String())
	stored, err := roles.Get(testContext(), ro.ID)
	require.NoError(t, err)
	assert.Equal(t, "ops", stored.Name)
	assertNotRevoked(t, users, alice)
}

// The rename is already stored when the members cannot be listed: keep
// today's response and log the missed revocation.
func TestRoleHandler_Update_Rename_ListMembersFails_200_Warns(t *testing.T) {
	roles := testutil.NewRoleRepo()
	users := testutil.NewUserRepo()
	alice := seedUser(t, users, "alice")
	ro := seedRoleWithMembers(t, roles, "ops", alice)
	core, logs := observer.New(zapcore.DebugLevel)
	h := handlers.NewRoleHandler(memberListFailingRoles{roles}, users).WithLogger(zap.New(core).Sugar())
	r := gin.New()
	r.PUT("/service/rest/v1/security/roles/:id", h.Update)

	rec := do(t, r, http.MethodPut, "/service/rest/v1/security/roles/"+ro.ID,
		map[string]any{"name": "ops2"})
	require.Equal(t, http.StatusOK, rec.Code)
	var got domain.Role
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	assert.Equal(t, "ops2", got.Name)
	stored, err := roles.Get(testContext(), ro.ID)
	require.NoError(t, err)
	assert.Equal(t, "ops2", stored.Name)
	assertNotRevoked(t, users, alice)

	entries := logs.FilterMessage("ListMemberIDs failed after role rename").All()
	require.Len(t, entries, 1)
	assert.Equal(t, zapcore.WarnLevel, entries[0].Level)
	assert.Equal(t, ro.ID, entries[0].ContextMap()["role"])
}

func TestRoleHandler_Delete_DeleteError_500_NoBump(t *testing.T) {
	roles := testutil.NewRoleRepo()
	users := testutil.NewUserRepo()
	alice := seedUser(t, users, "alice")
	ro := seedRoleWithMembers(t, roles, "ops", alice)
	h := handlers.NewRoleHandler(deleteFailingRoles{roles}, users)
	r := gin.New()
	r.DELETE("/service/rest/v1/security/roles/:id", h.Delete)

	rec := do(t, r, http.MethodDelete, "/service/rest/v1/security/roles/"+ro.ID, nil)
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	assertNotRevoked(t, users, alice)
}
