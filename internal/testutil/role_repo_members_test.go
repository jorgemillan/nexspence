package testutil_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nexspence-oss/nexspence/internal/domain"
	"github.com/nexspence-oss/nexspence/internal/testutil"
)

func TestRoleRepoFake_ListMemberIDs(t *testing.T) {
	ctx := context.Background()
	repo := testutil.NewRoleRepo()
	ops := &domain.Role{Name: "ops"}
	dev := &domain.Role{Name: "dev"}
	empty := &domain.Role{Name: "empty"}
	for _, ro := range []*domain.Role{ops, dev, empty} {
		if err := repo.Create(ctx, ro); err != nil {
			t.Fatal(err)
		}
	}
	for user, roleIDs := range map[string][]string{
		"user-2": {ops.ID, dev.ID},
		"user-1": {ops.ID},
		"user-3": {dev.ID},
	} {
		if err := repo.SetUserRoles(ctx, user, roleIDs); err != nil {
			t.Fatal(err)
		}
	}

	got, err := repo.ListMemberIDs(ctx, ops.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "user-1" || got[1] != "user-2" {
		t.Fatalf("ops members: want [user-1 user-2], got %v", got)
	}

	got, err = repo.ListMemberIDs(ctx, empty.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("empty role: want a non-nil empty slice, got %#v", got)
	}

	repo.Err = errors.New("db down")
	if _, err := repo.ListMemberIDs(ctx, ops.ID); err == nil {
		t.Fatal("want the repo error")
	}
}
