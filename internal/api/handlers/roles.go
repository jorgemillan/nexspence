package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/nexspence-oss/nexspence/internal/domain"
	"github.com/nexspence-oss/nexspence/internal/repository"
)

// RoleHandler handles role CRUD and user-role assignment.
type RoleHandler struct {
	roles repository.RoleRepo
	users repository.UserRepo
}

// NewRoleHandler constructs a RoleHandler from the role and user repositories.
func NewRoleHandler(roles repository.RoleRepo, users repository.UserRepo) *RoleHandler {
	return &RoleHandler{roles: roles, users: users}
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
	// Built-in roles come only from the seed migration; the API never creates one.
	ro.ReadOnly = false
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
	if _, ok := h.mutableRole(c, ro.ID); !ok {
		return
	}
	if err := h.roles.Update(c.Request.Context(), &ro); err != nil {
		if conflictOnDuplicateName(c, err) {
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
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
	if _, ok := h.mutableRole(c, id); !ok {
		return
	}
	if err := h.roles.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
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
	c.Status(http.StatusNoContent)
}

// errBuiltinRole is the answer to a change of a built-in role.
const errBuiltinRole = "built-in role cannot be modified or deleted"

// mutableRole reads the role a PUT or DELETE targets and reports whether the
// request may go on, answering the client itself when it may not. Built-in
// roles are refused: being an admin means holding the role named nx-admin, so
// renaming, emptying or deleting it locks every admin out. An unknown id goes
// on as before (role is nil); any other read error is a 500, so a failing
// database never lets a built-in role through.
func (h *RoleHandler) mutableRole(c *gin.Context, id string) (*domain.Role, bool) {
	role, err := h.roles.Get(c.Request.Context(), id)
	switch {
	case errors.Is(err, repository.ErrNotFound):
		return nil, true
	case err != nil:
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return nil, false
	case role.ReadOnly:
		c.JSON(http.StatusBadRequest, gin.H{"error": errBuiltinRole})
		return nil, false
	}
	return role, true
}
