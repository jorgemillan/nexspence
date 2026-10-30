//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nexspence-oss/nexspence/internal/testutil/pgtest"
)

// A JWT carries the role names it was issued with, and nx-admin is decided
// from that claim. Changing who holds a role name must therefore revoke the
// affected users' earlier JWTs, as disabling them or changing their password
// already does. The server is shared, so these tests only touch t46-* roles
// and only read nx-admin.

const t46Password = "t46Pass123!"

// t46Role creates a role without privileges; it is deleted when the test ends,
// after the users created later in the test.
func t46Role(t *testing.T, admin, name string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"name": name})
	id := createdID(t, authReq(t, http.MethodPost, "/service/rest/v1/security/roles", bytes.NewReader(body), admin))
	t.Cleanup(func() {
		d := authReq(t, http.MethodDelete, "/service/rest/v1/security/roles/"+id, nil, admin)
		d.Body.Close()
	})
	return id
}

// t46User creates an active local user holding roleIDs, assigned with
// PUT .../roles as the UI does, and returns its JWT. The account is removed
// when the test ends.
func t46User(t *testing.T, admin, username string, roleIDs ...string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"userId": username, "emailAddress": username + "@example.com", "password": t46Password,
		"status": "active", "roles": []string{},
	})
	resp := authReq(t, http.MethodPost, "/service/rest/v1/security/users", bytes.NewReader(body), admin)
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode, "%s", raw)
	t.Cleanup(func() {
		d := authReq(t, http.MethodDelete, "/service/rest/v1/security/users/"+username, nil, admin)
		d.Body.Close()
	})
	if len(roleIDs) > 0 {
		setRoles(t, admin, username, roleIDs...)
	}
	return t46Login(t, username)
}

// t46Login rewinds the user's revocation cutoff before logging in, as
// selectorUser does: a JWT's iat is whole seconds, so one issued in the
// same second as the last cutoff move would read as revoked.
func t46Login(t *testing.T, username string) string {
	t.Helper()
	_, err := pgtest.Pool(t).Exec(context.Background(),
		`UPDATE users SET tokens_valid_after = now() - interval '1 minute' WHERE username = $1`, username)
	require.NoError(t, err)
	return login(t, username, t46Password)
}

// setRoles replaces the user's roles through the admin endpoint.
func setRoles(t *testing.T, admin, username string, roleIDs ...string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"roleIds": append([]string{}, roleIDs...)})
	resp := authReq(t, http.MethodPut, "/service/rest/v1/security/users/"+username+"/roles", bytes.NewReader(body), admin)
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusNoContent, resp.StatusCode, "%s", raw)
}

func statusOf(t *testing.T, method, path, token string, body io.Reader) int {
	t.Helper()
	resp := authReq(t, method, path, body, token)
	resp.Body.Close()
	return resp.StatusCode
}

// dockerJWT asks /v2/token for a JWT with Basic credentials, as docker login does.
func dockerJWT(t *testing.T, username, password string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, server(t).URL+"/v2/token", nil)
	require.NoError(t, err)
	req.SetBasicAuth(username, password)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%s", raw)
	var out struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(raw, &out))
	require.NotEmpty(t, out.Token)
	return out.Token
}

// basicStatus sends a GET with Basic credentials.
func basicStatus(t *testing.T, path, username, password string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, server(t).URL+path, nil)
	require.NoError(t, err)
	req.SetBasicAuth(username, password)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	return resp.StatusCode
}

var revokedJWTPaths = []string{"/service/rest/v1/security/users", "/api/v1/me", "/api/v1/me/privileges"}

func TestRoleChange_RemoveAdmin_RevokesPreviousJWT(t *testing.T) {
	admin := login(t, "admin", "admin123")
	const user = "t46-remove-admin"
	prev := t46User(t, admin, user, roleID(t, admin, "nx-admin"))
	require.Equal(t, http.StatusOK, statusOf(t, http.MethodGet, "/service/rest/v1/security/users", prev, nil))

	setRoles(t, admin, user)

	for _, p := range revokedJWTPaths {
		assert.Equal(t, http.StatusUnauthorized, statusOf(t, http.MethodGet, p, prev, nil), "GET %s with the JWT issued as nx-admin", p)
	}
	// Only after checking the old JWT: the rewind would un-revoke it.
	fresh := t46Login(t, user)
	assert.Equal(t, http.StatusForbidden, statusOf(t, http.MethodGet, "/service/rest/v1/security/users", fresh, nil))
	assert.Equal(t, http.StatusOK, statusOf(t, http.MethodGet, "/api/v1/me", fresh, nil))
}

func TestRoleChange_GrantAdmin_RevokesPreviousJWT(t *testing.T) {
	admin := login(t, "admin", "admin123")
	const user = "t46-grant-admin"
	prev := t46User(t, admin, user)
	require.Equal(t, http.StatusForbidden, statusOf(t, http.MethodGet, "/service/rest/v1/security/users", prev, nil))

	setRoles(t, admin, user, roleID(t, admin, "nx-admin"))

	assert.Equal(t, http.StatusUnauthorized, statusOf(t, http.MethodGet, "/service/rest/v1/security/users", prev, nil))
	assert.Equal(t, http.StatusUnauthorized, statusOf(t, http.MethodGet, "/api/v1/me", prev, nil))
	fresh := t46Login(t, user)
	assert.Equal(t, http.StatusOK, statusOf(t, http.MethodGet, "/service/rest/v1/security/users", fresh, nil))
}

// JWTs from /v2/token — with the password or exchanged for an API token —
// embed the roles too and are revoked the same way. The API token and Basic
// auth themselves load the roles per request and keep working with the new set.
func TestRoleChange_RevokesDockerAndAPITokenJWTs(t *testing.T) {
	admin := login(t, "admin", "admin123")
	const user = "t46-docker"
	rID := t46Role(t, admin, "t46-docker-role")
	own := t46User(t, admin, user, rID)
	code, apiToken := mintToken(t, own, `{"name":"t46-docker"}`)
	require.Equal(t, http.StatusCreated, code)
	require.True(t, strings.HasPrefix(apiToken, "nxs_"))

	passwordJWT := dockerJWT(t, user, t46Password)
	exchangedJWT := dockerJWT(t, user, apiToken)
	require.Equal(t, http.StatusOK, statusOf(t, http.MethodGet, "/api/v1/me", passwordJWT, nil))
	require.Equal(t, http.StatusOK, statusOf(t, http.MethodGet, "/api/v1/me", exchangedJWT, nil))

	setRoles(t, admin, user)

	assert.Equal(t, http.StatusUnauthorized, statusOf(t, http.MethodGet, "/api/v1/me", passwordJWT, nil), "/v2/token JWT from the password")
	assert.Equal(t, http.StatusUnauthorized, statusOf(t, http.MethodGet, "/api/v1/me", exchangedJWT, nil), "/v2/token JWT exchanged for the API token")

	// The API token and Basic auth keep working and see the new (empty) set.
	resp := authReq(t, http.MethodGet, "/api/v1/me", nil, apiToken)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var me struct {
		Roles []string `json:"roles"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&me))
	assert.Empty(t, me.Roles)
	assert.Equal(t, http.StatusOK, basicStatus(t, "/api/v1/me", user, t46Password))
}

func TestRoleChange_OtherUsersKeepJWT(t *testing.T) {
	admin := login(t, "admin", "admin123")
	rID := t46Role(t, admin, "t46-others-role")
	t46User(t, admin, "t46-others-changed", rID)
	other := t46User(t, admin, "t46-others-kept", rID)

	setRoles(t, admin, "t46-others-changed")

	assert.Equal(t, http.StatusOK, statusOf(t, http.MethodGet, "/api/v1/me", other, nil), "a user whose roles did not change")
	assert.Equal(t, http.StatusOK, statusOf(t, http.MethodGet, "/service/rest/v1/security/users", admin, nil), "the admin who made the change")
}

func TestRoleDelete_RevokesMembersOnly(t *testing.T) {
	admin := login(t, "admin", "admin123")
	rID := t46Role(t, admin, "t46-del")
	otherID := t46Role(t, admin, "t46-del-other")
	m1 := t46User(t, admin, "t46-del-m1", rID)
	m2 := t46User(t, admin, "t46-del-m2", rID, otherID)
	nonMember := t46User(t, admin, "t46-del-nonmember", otherID)
	for _, tok := range []string{m1, m2, nonMember} {
		require.Equal(t, http.StatusOK, statusOf(t, http.MethodGet, "/api/v1/me", tok, nil))
	}

	require.Equal(t, http.StatusNoContent, statusOf(t, http.MethodDelete, "/service/rest/v1/security/roles/"+rID, admin, nil))

	assert.Equal(t, http.StatusUnauthorized, statusOf(t, http.MethodGet, "/api/v1/me", m1, nil), "member")
	assert.Equal(t, http.StatusUnauthorized, statusOf(t, http.MethodGet, "/api/v1/me", m2, nil), "member with another role")
	assert.Equal(t, http.StatusOK, statusOf(t, http.MethodGet, "/api/v1/me", nonMember, nil), "not a member")
	assert.Equal(t, http.StatusOK, statusOf(t, http.MethodGet, "/service/rest/v1/security/users", admin, nil), "admin")
}

func TestRoleRename_RevokesMembers_DescriptionDoesNot(t *testing.T) {
	admin := login(t, "admin", "admin123")
	rID := t46Role(t, admin, "t46-ren")
	member := t46User(t, admin, "t46-ren-member", rID)
	path := "/service/rest/v1/security/roles/" + rID

	require.Equal(t, http.StatusOK, statusOf(t, http.MethodPut, path, admin,
		strings.NewReader(`{"name":"t46-ren","description":"only the description"}`)))
	assert.Equal(t, http.StatusOK, statusOf(t, http.MethodGet, "/api/v1/me", member, nil), "description change keeps the JWT")

	require.Equal(t, http.StatusOK, statusOf(t, http.MethodPut, path, admin,
		strings.NewReader(`{"name":"t46-ren-renamed"}`)))
	assert.Equal(t, http.StatusUnauthorized, statusOf(t, http.MethodGet, "/api/v1/me", member, nil), "rename revokes the member's JWT")
}
