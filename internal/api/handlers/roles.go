package handlers

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/nexspence-oss/nexspence/internal/domain"
	"github.com/nexspence-oss/nexspence/internal/logger"
	"github.com/nexspence-oss/nexspence/internal/repository"
)

// RoleHandler handles role CRUD and user-role assignment.
type RoleHandler struct {
	roles repository.RoleRepo
	users repository.UserRepo
	log   logger.Logger
}

// NewRoleHandler constructs a RoleHandler from the role and user repositories.
func NewRoleHandler(roles repository.RoleRepo, users repository.UserRepo) *RoleHandler {
	return &RoleHandler{roles: roles, users: users}
}

// WithLogger wires a logger for failed JWT revocations, which do not fail
// the request; returns the handler for chaining.
func (h *RoleHandler) WithLogger(log logger.Logger) *RoleHandler {
	h.log = log
	return h
}

// revokeTokens moves the revocation cutoff of each user. A JWT embeds the
// role names it was issued with, so any change to who holds a role name must
// revoke the affected users' earlier JWTs. Called after the change is stored:
// a failed bump is logged and does not undo it.
func (h *RoleHandler) revokeTokens(ctx context.Context, userIDs []string, reason string, kv ...any) {
	for _, id := range userIDs {
		if err := h.users.BumpTokensValidAfter(ctx, id); err != nil && h.log != nil {
			h.log.Warnw("BumpTokensValidAfter failed after "+reason, append([]any{"user", id, "err", err}, kv...)...)
		}
	}
}

// List handles GET /service/rest/v1/security/roles
func (h *RoleHandler) List(c *gin.Context) {
	roles, err := h.roles.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if roles == nil {
		roles = []domain.Role{}
	}
	c.JSON(http.StatusOK, roles)
}

// Create handles POST /service/rest/v1/security/roles
func (h *RoleHandler) Create(c *gin.Context) {
	var ro domain.Role
	if err := c.ShouldBindJSON(&ro); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if ro.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	ro.Source = "default"
	if err := h.roles.Create(c.Request.Context(), &ro); err != nil {
		if conflictOnDuplicateName(c, err) {
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if len(ro.Privileges) > 0 {
		if err := h.roles.SetPrivileges(c.Request.Context(), ro.ID, ro.Privileges); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}
	c.JSON(http.StatusCreated, ro)
}

// Update handles PUT /service/rest/v1/security/roles/:id
func (h *RoleHandler) Update(c *gin.Context) {
	var ro domain.Role
	if err := c.ShouldBindJSON(&ro); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ro.ID = c.Param("id")
	// Read the current name first: renaming changes what members' JWTs mean.
	prevName, renamable := "", false
	prev, err := h.roles.Get(c.Request.Context(), ro.ID)
	switch {
	case err == nil:
		prevName, renamable = prev.Name, true
	case !errors.Is(err, repository.ErrNotFound):
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := h.roles.Update(c.Request.Context(), &ro); err != nil {
		if conflictOnDuplicateName(c, err) {
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// Revoke before the privileges step, so a failure there does not leave
	// a stored rename unrevoked.
	if renamable && prevName != ro.Name {
		members, err := h.roles.ListMemberIDs(c.Request.Context(), ro.ID)
		if err != nil {
			if h.log != nil {
				h.log.Warnw("ListMemberIDs failed after role rename", "role", ro.ID, "err", err)
			}
		} else {
			h.revokeTokens(c.Request.Context(), members, "role rename", "role", ro.ID)
		}
	}
	// No "privileges" key means "unchanged": a client that edits only the
	// name and description must not empty the role. An explicit list, empty
	// included, replaces it.
	if ro.Privileges == nil {
		ids, err := h.roles.ListPrivilegeIDsByRole(c.Request.Context(), ro.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		ro.Privileges = ids
	} else if err := h.roles.SetPrivileges(c.Request.Context(), ro.ID, ro.Privileges); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, ro)
}

// Delete handles DELETE /service/rest/v1/security/roles/:id
func (h *RoleHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	// Read the members before deleting: the delete cascades to user_roles.
	members, err := h.roles.ListMemberIDs(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := h.roles.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	h.revokeTokens(c.Request.Context(), members, "role delete", "role", id)
	c.Status(http.StatusNoContent)
}

// SetUserRoles handles PUT /service/rest/v1/security/users/:userId/roles
// Body: {"roleIds": ["uuid1", "uuid2"]}
func (h *RoleHandler) SetUserRoles(c *gin.Context) {
	username := c.Param("userId")
	var req struct {
		RoleIDs []string `json:"roleIds"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	user, err := h.users.Get(c.Request.Context(), username)
	if err != nil || user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found: " + username})
		return
	}
	if err := h.roles.SetUserRoles(c.Request.Context(), user.ID, req.RoleIDs); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	h.revokeTokens(c.Request.Context(), []string{user.ID}, "role change")
	c.Status(http.StatusNoContent)
}
