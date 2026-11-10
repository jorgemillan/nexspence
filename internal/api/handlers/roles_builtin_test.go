package handlers_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nexspence-oss/nexspence/internal/api/handlers"
	"github.com/nexspence-oss/nexspence/internal/domain"
	"github.com/nexspence-oss/nexspence/internal/repository"
	"github.com/nexspence-oss/nexspence/internal/testutil"
)

// The seed migration creates five built-in roles (roles.builtin, readOnly in
// the API). Being an admin means holding a role named nx-admin, so renaming,
// emptying or deleting that role locks every admin out. PUT and DELETE on a
// built-in role are refused before anything is written.

const builtinRejectedBody = `{"error":"built-in role cannot be modified or deleted"}`

// builtinSpyRoles counts the writes a rejected request must never reach.
type builtinSpyRoles struct {
	*testutil.RoleRepo
	updates, deletes, setPrivileges, listMembers int
}

func (r *builtinSpyRoles) Update(ctx context.Context, role *domain.Role) error {
	r.updates++
	return r.RoleRepo.Update(ctx, role)
}

func (r *builtinSpyRoles) Delete(ctx context.Context, id string) error {
	r.deletes++
	return r.RoleRepo.Delete(ctx, id)
}

func (r *builtinSpyRoles) SetPrivileges(ctx context.Context, roleID string, privilegeIDs []string) error {
	r.setPrivileges++
	return r.RoleRepo.SetPrivileges(ctx, roleID, privilegeIDs)
}

// ListMemberIDs only counts: a handler that reads a role's members before
// changing it must not do so for a built-in role it is about to refuse.
func (r *builtinSpyRoles) ListMemberIDs(context.Context, string) ([]string, error) {
	r.listMembers++
	return nil, nil
}

// builtinSpyUsers counts token revocations.
type builtinSpyUsers struct {
	*testutil.UserRepo
	bumps int
}

func (u *builtinSpyUsers) BumpTokensValidAfter(ctx context.Context, userID string) error {
	u.bumps++
	return u.UserRepo.BumpTokensValidAfter(ctx, userID)
}

// builtinGetErrRoles fails the read that decides whether a role is built-in.
type builtinGetErrRoles struct{ *builtinSpyRoles }

func (builtinGetErrRoles) Get(context.Context, string) (*domain.Role, error) {
	return nil, errors.New("db down")
}

func mountBuiltinRoles(t *testing.T, roles repository.RoleRepo, users repository.UserRepo) *gin.Engine {
	t.Helper()
	h := handlers.NewRoleHandler(roles, users)
	r := gin.New()
	r.GET("/service/rest/v1/security/roles", h.List)
	r.POST("/service/rest/v1/security/roles", h.Create)
	r.PUT("/service/rest/v1/security/roles/:id", h.Update)
	r.DELETE("/service/rest/v1/security/roles/:id", h.Delete)
	r.PUT("/service/rest/v1/security/users/:userId/roles", h.SetUserRoles)
	return r
}

// seedBuiltinRoles mirrors the built-in rows of 001_initial.sql.
func seedBuiltinRoles() []*domain.Role {
	return []*domain.Role{
		{ID: "builtin-nx-admin", Name: "nx-admin", Description: "Administrator with all privileges", ReadOnly: true},
		{ID: "builtin-nx-anonymous", Name: "nx-anonymous", Description: "Anonymous access role", ReadOnly: true},
		{ID: "builtin-nx-developer", Name: "nx-developer", Description: "Developer — read/write access", ReadOnly: true},
		{ID: "builtin-nx-deployer", Name: "nx-deployer", Description: "Deployer — upload artifacts", ReadOnly: true},
		{ID: "builtin-nx-replication", Name: "nx-replication", Description: "Replication service account", ReadOnly: true},
	}
}

// newBuiltinRoles seeds the built-in roles, each with one privilege so that a
// privilege change would show.
func newBuiltinRoles(t *testing.T) ([]*domain.Role, *builtinSpyRoles) {
	t.Helper()
	seeded := seedBuiltinRoles()
	roles := &builtinSpyRoles{RoleRepo: testutil.NewRoleRepo(seeded...)}
	for _, role := range seeded {
		require.NoError(t, roles.RoleRepo.SetPrivileges(testContext(), role.ID, []string{"priv-" + role.Name}))
	}
	return seeded, roles
}

// assertRoleUntouched compares against a copy taken before the request: the
// fake stores and hands back the caller's pointer, and its Update replaces it.
func assertRoleUntouched(t *testing.T, roles *builtinSpyRoles, seeded *domain.Role, before domain.Role) {
	t.Helper()
	got, err := roles.Get(testContext(), seeded.ID)
	require.NoError(t, err, "role %s is gone", before.Name)
	assert.Same(t, seeded, got, "role %s was replaced", before.Name)
	assert.Equal(t, before, *got, "role %s changed", before.Name)
	assert.Equal(t, []string{"priv-" + before.Name}, roles.PrivilegesOf(seeded.ID), "privileges of %s changed", before.Name)
}

func TestRoleHandler_Builtin_Delete_400_Untouched(t *testing.T) {
	for i, role := range seedBuiltinRoles() {
		t.Run(role.Name, func(t *testing.T) {
			seeded, roles := newBuiltinRoles(t)
			r := mountBuiltinRoles(t, roles, testutil.NewUserRepo())
			target := seeded[i]
			before := *target

			rec := do(t, r, http.MethodDelete, "/service/rest/v1/security/roles/"+target.ID, nil)

			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.JSONEq(t, builtinRejectedBody, rec.Body.String())
			assert.Zero(t, roles.deletes, "Delete reached the repository")
			assertRoleUntouched(t, roles, target, before)
		})
	}
}

func TestRoleHandler_Builtin_Update_400_Untouched(t *testing.T) {
	bodies := []struct {
		name string
		body func(role domain.Role) map[string]any
	}{
		{"rename", func(role domain.Role) map[string]any {
			return map[string]any{"name": role.Name + "-renamed", "description": role.Description}
		}},
		{"same name, other description", func(role domain.Role) map[string]any {
			return map[string]any{"name": role.Name, "description": "changed"}
		}},
		{"no name", func(role domain.Role) map[string]any {
			return map[string]any{"description": "changed"}
		}},
		{"same name, empty privileges", func(role domain.Role) map[string]any {
			return map[string]any{"name": role.Name, "description": role.Description, "privileges": []string{}}
		}},
	}
	for i, role := range seedBuiltinRoles() {
		for _, b := range bodies {
			t.Run(role.Name+"/"+b.name, func(t *testing.T) {
				seeded, roles := newBuiltinRoles(t)
				r := mountBuiltinRoles(t, roles, testutil.NewUserRepo())
				target := seeded[i]
				before := *target

				rec := do(t, r, http.MethodPut, "/service/rest/v1/security/roles/"+target.ID, b.body(before))

				assert.Equal(t, http.StatusBadRequest, rec.Code)
				assert.JSONEq(t, builtinRejectedBody, rec.Body.String())
				assert.Zero(t, roles.updates, "Update reached the repository")
				assert.Zero(t, roles.setPrivileges, "SetPrivileges reached the repository")
				assertRoleUntouched(t, roles, target, before)
			})
		}
	}
}

// A refused change writes nothing and revokes nobody: the members of nx-admin
// keep their role and their tokens.
func TestRoleHandler_Builtin_Rejected_NoMemberListNoBump(t *testing.T) {
	requests := []struct {
		name   string
		method string
		body   any
	}{
		{"delete", http.MethodDelete, nil},
		{"rename", http.MethodPut, map[string]any{"name": "nx-admin-renamed"}},
	}
	for _, req := range requests {
		t.Run(req.name, func(t *testing.T) {
			seeded, roles := newBuiltinRoles(t)
			admin := seeded[0]
			before := *admin
			member := &domain.User{ID: "u-member", Username: "member"}
			users := &builtinSpyUsers{UserRepo: testutil.NewUserRepo(member)}
			require.NoError(t, roles.SetUserRoles(testContext(), member.ID, []string{admin.ID}))
			r := mountBuiltinRoles(t, roles, users)

			rec := do(t, r, req.method, "/service/rest/v1/security/roles/"+admin.ID, req.body)

			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.JSONEq(t, builtinRejectedBody, rec.Body.String())
			assert.Zero(t, roles.updates, "Update reached the repository")
			assert.Zero(t, roles.deletes, "Delete reached the repository")
			assert.Zero(t, roles.listMembers, "members were listed for a refused change")
			assert.Zero(t, users.bumps, "tokens were revoked for a refused change")
			assert.Equal(t, []string{admin.ID}, roles.UserRoleIDs(member.ID))
			assertRoleUntouched(t, roles, admin, before)
		})
	}
}

// The body is bound before the role is read: malformed JSON is gin's 400 on
// any role, built-in or not.
func TestRoleHandler_Builtin_Update_BadJSON_400(t *testing.T) {
	seeded, roles := newBuiltinRoles(t)
	r := mountBuiltinRoles(t, roles, testutil.NewUserRepo())
	admin := seeded[0]
	before := *admin

	rec := doRaw(t, r, http.MethodPut, "/service/rest/v1/security/roles/"+admin.ID, []byte(`{bad`))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.NotContains(t, rec.Body.String(), "built-in role")
	assert.Zero(t, roles.updates)
	assertRoleUntouched(t, roles, admin, before)
}

// When the role cannot be read, nothing is written: a failing database must
// not let a built-in role through.
func TestRoleHandler_Builtin_GetError_500_NoWrite(t *testing.T) {
	_, spy := newBuiltinRoles(t)
	roles := builtinGetErrRoles{spy}
	r := mountBuiltinRoles(t, roles, testutil.NewUserRepo())

	rec := do(t, r, http.MethodPut, "/service/rest/v1/security/roles/builtin-nx-admin", map[string]any{"name": "nx-admin-renamed"})
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.JSONEq(t, `{"error":"db down"}`, rec.Body.String())

	rec = do(t, r, http.MethodDelete, "/service/rest/v1/security/roles/builtin-nx-admin", nil)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.JSONEq(t, `{"error":"db down"}`, rec.Body.String())

	assert.Zero(t, spy.updates, "Update reached the repository")
	assert.Zero(t, spy.deletes, "Delete reached the repository")
	assert.Zero(t, spy.setPrivileges, "SetPrivileges reached the repository")
}

// Built-in roles come only from the seed migration: a client-sent readOnly is
// ignored, and the role it creates stays deletable.
func TestRoleHandler_Create_ReadOnlyTrue_StoredFalse(t *testing.T) {
	roles := testutil.NewRoleRepo()
	r := mountBuiltinRoles(t, roles, testutil.NewUserRepo())

	rec := do(t, r, http.MethodPost, "/service/rest/v1/security/roles", map[string]any{"name": "ro", "readOnly": true})
	require.Equal(t, http.StatusCreated, rec.Code)
	var created domain.Role
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	assert.False(t, created.ReadOnly, "response says readOnly")
	stored, err := roles.Get(testContext(), created.ID)
	require.NoError(t, err)
	assert.False(t, stored.ReadOnly, "role stored as built-in")

	rec = do(t, r, http.MethodDelete, "/service/rest/v1/security/roles/"+created.ID, nil)
	assert.Equal(t, http.StatusNoContent, rec.Code)
	_, err = roles.Get(testContext(), created.ID)
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

func TestRoleHandler_Custom_UpdateDelete_Unchanged(t *testing.T) {
	custom := &domain.Role{ID: "custom-1", Name: "custom", Description: "before"}
	roles := &builtinSpyRoles{RoleRepo: testutil.NewRoleRepo(custom)}
	require.NoError(t, roles.RoleRepo.SetPrivileges(testContext(), custom.ID, []string{"p1", "p2"}))
	r := mountBuiltinRoles(t, roles, testutil.NewUserRepo())
	path := "/service/rest/v1/security/roles/" + custom.ID

	rec := do(t, r, http.MethodPut, path, map[string]any{"name": "custom", "description": "after"})
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 1, roles.updates)
	got, err := roles.Get(testContext(), custom.ID)
	require.NoError(t, err)
	assert.Equal(t, "after", got.Description)
	assert.Equal(t, []string{"p1", "p2"}, roles.PrivilegesOf(custom.ID))

	rec = do(t, r, http.MethodPut, path, map[string]any{"name": "custom-renamed", "description": "after"})
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 2, roles.updates)
	got, err = roles.Get(testContext(), custom.ID)
	require.NoError(t, err)
	assert.Equal(t, "custom-renamed", got.Name)

	rec = do(t, r, http.MethodDelete, path, nil)
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, 1, roles.deletes)
	_, err = roles.Get(testContext(), custom.ID)
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

// An unknown id is not a built-in role: the request goes on as before.
func TestRoleHandler_UnknownID_Unchanged(t *testing.T) {
	const unknown = "00000000-0000-4000-8000-000000000048"
	_, roles := newBuiltinRoles(t)
	r := mountBuiltinRoles(t, roles, testutil.NewUserRepo())

	rec := do(t, r, http.MethodDelete, "/service/rest/v1/security/roles/"+unknown, nil)
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, 1, roles.deletes)

	rec = do(t, r, http.MethodPut, "/service/rest/v1/security/roles/"+unknown, map[string]any{"name": "ghost"})
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 1, roles.updates)
}
