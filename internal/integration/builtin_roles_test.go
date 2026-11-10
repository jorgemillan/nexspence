//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nexspence-oss/nexspence/internal/testutil/pgtest"
)

// Being an admin means holding the role named nx-admin, so deleting or
// renaming it through the API locked every admin out for good. PUT and DELETE
// on any of the five seeded built-in roles are now refused with a fixed 400.

const builtinRoleRejected = `{"error":"built-in role cannot be modified or deleted"}`

var builtinRoleNames = []string{"nx-admin", "nx-anonymous", "nx-developer", "nx-deployer", "nx-replication"}

type builtinRoleRow struct {
	ID, Name, Description, Source string
	Builtin                       bool
}

// snapshotBuiltinRoles records the built-in roles and their assignments and
// returns a function that puts them back. The server and database are shared
// by the whole package: without the fix a test here deletes nx-admin, and the
// restore keeps that from breaking every test after it. With the fix it
// rewrites the same values.
func snapshotBuiltinRoles(t *testing.T) func() {
	t.Helper()
	ctx := context.Background()
	pool := pgtest.Pool(t)

	var roles []builtinRoleRow
	rows, err := pool.Query(ctx, `SELECT id::text, name, description, source, builtin FROM roles WHERE builtin ORDER BY name`)
	require.NoError(t, err)
	for rows.Next() {
		var r builtinRoleRow
		require.NoError(t, rows.Scan(&r.ID, &r.Name, &r.Description, &r.Source, &r.Builtin))
		roles = append(roles, r)
	}
	rows.Close()
	require.NoError(t, rows.Err())
	require.Len(t, roles, len(builtinRoleNames), "seeded built-in roles")

	pairs := func(query string) [][2]string {
		rows, err := pool.Query(ctx, query)
		require.NoError(t, err)
		defer rows.Close()
		var out [][2]string
		for rows.Next() {
			var p [2]string
			require.NoError(t, rows.Scan(&p[0], &p[1]))
			out = append(out, p)
		}
		require.NoError(t, rows.Err())
		return out
	}
	userRoles := pairs(`SELECT ur.user_id::text, ur.role_id::text FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE r.builtin`)
	rolePrivs := pairs(`SELECT rp.role_id::text, rp.privilege_id::text FROM role_privileges rp JOIN roles r ON r.id = rp.role_id WHERE r.builtin`)

	return func() {
		for _, r := range roles {
			_, err := pool.Exec(ctx, `
				INSERT INTO roles (id, name, description, source, builtin) VALUES ($1, $2, $3, $4, $5)
				ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description,
					source = EXCLUDED.source, builtin = EXCLUDED.builtin`,
				r.ID, r.Name, r.Description, r.Source, r.Builtin)
			assert.NoError(t, err, "restore role %s", r.Name)
		}
		for _, p := range userRoles {
			_, err := pool.Exec(ctx, `INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, p[0], p[1])
			assert.NoError(t, err, "restore user_roles %v", p)
		}
		for _, p := range rolePrivs {
			_, err := pool.Exec(ctx, `INSERT INTO role_privileges (role_id, privilege_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, p[0], p[1])
			assert.NoError(t, err, "restore role_privileges %v", p)
		}
	}
}

// basicAuthStatus sends the request with Basic auth, which reads the user's
// roles from the database on every request: it shows a lost nx-admin that a
// JWT issued earlier would still hide.
func basicAuthStatus(t *testing.T, method, path, user, pass string) int {
	t.Helper()
	req, err := http.NewRequest(method, server(t).URL+path, nil)
	require.NoError(t, err)
	req.SetBasicAuth(user, pass)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	return resp.StatusCode
}

type builtinRoleView struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	ReadOnly    bool   `json:"readOnly"`
}

func listRoleViews(t *testing.T, admin string) map[string]builtinRoleView {
	t.Helper()
	resp := authReq(t, http.MethodGet, "/service/rest/v1/security/roles", nil, admin)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var roles []builtinRoleView
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&roles))
	byID := make(map[string]builtinRoleView, len(roles))
	for _, r := range roles {
		byID[r.ID] = r
	}
	return byID
}

func roleRequest(t *testing.T, method, id, body, token string) (int, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = bytes.NewBufferString(body)
	}
	resp := authReq(t, method, "/service/rest/v1/security/roles/"+id, rdr, token)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(raw)
}

func TestBuiltinRoles_DeleteRejected_AdminKeepsAccess(t *testing.T) {
	admin := login(t, "admin", "admin123")
	before := listRoleViews(t, admin)
	ids := make(map[string]string, len(builtinRoleNames))
	for _, name := range builtinRoleNames {
		ids[name] = roleID(t, admin, name)
	}
	t.Cleanup(snapshotBuiltinRoles(t))

	for _, name := range builtinRoleNames {
		code, body := roleRequest(t, http.MethodDelete, ids[name], "", admin)
		if assert.Equal(t, http.StatusBadRequest, code, "DELETE %s", name) {
			assert.JSONEq(t, builtinRoleRejected, body, "DELETE %s", name)
		}
	}

	after := listRoleViews(t, admin)
	for _, name := range builtinRoleNames {
		assert.Equal(t, before[ids[name]], after[ids[name]], "role %s after DELETE", name)
	}
	assert.Equal(t, http.StatusOK,
		basicAuthStatus(t, http.MethodGet, "/service/rest/v1/security/users", "admin", "admin123"),
		"admin over Basic auth after deleting the built-in roles")
}

func TestBuiltinRoles_UpdateRejected_AdminKeepsAccess(t *testing.T) {
	admin := login(t, "admin", "admin123")
	id := roleID(t, admin, "nx-admin")
	before := listRoleViews(t, admin)[id]
	t.Cleanup(snapshotBuiltinRoles(t))

	// The renaming body goes last: without the fix it is the one that leaves
	// the admin locked out for the checks below.
	bodies := map[string]string{
		"same name, other description": `{"name":"nx-admin","description":"builtin-roles-test"}`,
		"no name":                      `{"description":"builtin-roles-test"}`,
		"rename":                       `{"name":"builtin-roles-test-admin","description":"builtin-roles-test"}`,
	}
	for _, label := range []string{"same name, other description", "no name", "rename"} {
		code, body := roleRequest(t, http.MethodPut, id, bodies[label], admin)
		if assert.Equal(t, http.StatusBadRequest, code, "PUT nx-admin, %s", label) {
			assert.JSONEq(t, builtinRoleRejected, body, "PUT nx-admin, %s", label)
		}
	}

	assert.Equal(t, before, listRoleViews(t, admin)[id], "nx-admin after PUT")
	assert.Equal(t, http.StatusOK,
		basicAuthStatus(t, http.MethodGet, "/service/rest/v1/security/users", "admin", "admin123"),
		"admin over Basic auth after changing nx-admin")
	fresh := login(t, "admin", "admin123")
	resp := authReq(t, http.MethodGet, "/service/rest/v1/security/users", nil, fresh)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "admin with a new login after changing nx-admin")
}

// A client cannot create a built-in role: readOnly in the body is ignored and
// the role it creates can be deleted.
func TestBuiltinRoles_CreateReadOnlyTrue_IsCustom(t *testing.T) {
	admin := login(t, "admin", "admin123")
	t.Cleanup(func() {
		_, err := pgtest.Pool(t).Exec(context.Background(), `DELETE FROM roles WHERE name = 'builtin-ro-test'`)
		assert.NoError(t, err)
	})

	resp := authReq(t, http.MethodPost, "/service/rest/v1/security/roles",
		bytes.NewBufferString(`{"name":"builtin-ro-test","readOnly":true}`), admin)
	raw, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "%s", raw)
	var created builtinRoleView
	require.NoError(t, json.Unmarshal(raw, &created))
	assert.False(t, created.ReadOnly, "POST response readOnly")
	assert.False(t, listRoleViews(t, admin)[created.ID].ReadOnly, "GET readOnly")

	var builtin bool
	require.NoError(t, pgtest.Pool(t).QueryRow(context.Background(),
		`SELECT builtin FROM roles WHERE id = $1`, created.ID).Scan(&builtin))
	assert.False(t, builtin, "roles.builtin")

	code, body := roleRequest(t, http.MethodDelete, created.ID, "", admin)
	assert.Equal(t, http.StatusNoContent, code, "%s", body)
}

// Authorization still runs first, and its answer does not depend on the role.
func TestBuiltinRoles_Negatives(t *testing.T) {
	admin := login(t, "admin", "admin123")
	id := roleID(t, admin, "nx-admin")
	before := listRoleViews(t, admin)[id]
	dev := loginAsDeveloper(t, admin, "builtin-roles-dev")

	bodies := map[string]string{http.MethodPut: `{"name":"builtin-roles-test-admin"}`, http.MethodDelete: ""}
	for method, body := range bodies {
		req, err := http.NewRequest(method, server(t).URL+"/service/rest/v1/security/roles/"+id, bytes.NewBufferString(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "%s nx-admin without credentials", method)

		code, got := roleRequest(t, method, id, body, dev)
		assert.Equal(t, http.StatusForbidden, code, "%s nx-admin as nx-developer", method)
		assert.JSONEq(t, `{"error":"admin role required"}`, got, "%s nx-admin as nx-developer", method)
	}
	assert.Equal(t, before, listRoleViews(t, admin)[id], "nx-admin after refused requests")
}

// An id that names no role is not a built-in role: the answer is the one it
// always was.
func TestBuiltinRoles_UnknownID_Unchanged(t *testing.T) {
	admin := login(t, "admin", "admin123")
	const unknown = "00000000-0000-4000-8000-000000000048"

	code, body := roleRequest(t, http.MethodPut, unknown, `{"name":"builtin-roles-ghost"}`, admin)
	assert.Equal(t, http.StatusOK, code, "PUT unknown id: %s", body)
	code, body = roleRequest(t, http.MethodDelete, unknown, "", admin)
	assert.Equal(t, http.StatusNoContent, code, "DELETE unknown id: %s", body)

	code, body = roleRequest(t, http.MethodPut, "not-a-uuid", `{"name":"builtin-roles-ghost"}`, admin)
	assert.Equal(t, http.StatusInternalServerError, code, "PUT not-a-uuid: %s", body)
	code, body = roleRequest(t, http.MethodDelete, "not-a-uuid", "", admin)
	assert.Equal(t, http.StatusInternalServerError, code, "DELETE not-a-uuid: %s", body)
}
