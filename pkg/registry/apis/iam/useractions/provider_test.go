package useractions

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	authnlib "github.com/grafana/authlib/authn"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/user"
)

type stubACService struct {
	accesscontrol.Service
	gotRequester identity.Requester
	permissions  []accesscontrol.Permission
}

func (s *stubACService) GetUserPermissions(_ context.Context, requester identity.Requester, _ accesscontrol.Options) ([]accesscontrol.Permission, error) {
	s.gotRequester = requester
	return s.permissions, nil
}

func TestUserPermissionsProvider_ActionsForUser(t *testing.T) {
	stub := &stubACService{permissions: []accesscontrol.Permission{
		{Action: "dashboards:read", Scope: "dashboards:*"},
		{Action: "dashboards:write", Scope: "dashboards:*"},
	}}
	provider := NewUserPermissionsProvider(stub)

	caller := &user.SignedInUser{
		UserID:         42,
		OrgID:          3,
		OrgRole:        org.RoleEditor,
		IsGrafanaAdmin: true,
		TeamIDs:        []int64{7},
	}

	actions, err := provider.ActionsForUser(context.Background(), caller)
	require.NoError(t, err)
	require.Equal(t, map[string]bool{"dashboards:read": true, "dashboards:write": true}, actions)

	t.Run("queries permissions with a synthetic role-only requester", func(t *testing.T) {
		synthetic, ok := stub.gotRequester.(*user.SignedInUser)
		require.True(t, ok)
		require.Equal(t, int64(3), synthetic.OrgID)
		require.Equal(t, org.RoleEditor, synthetic.OrgRole)
		require.True(t, synthetic.IsGrafanaAdmin)
		require.Zero(t, synthetic.UserID, "must not carry the user id, or per-user permissions would be included")
		require.Empty(t, synthetic.GetTeams(), "must not carry teams, or team permissions would be included")
		require.False(t, synthetic.HasUniqueId(), "must stay on the uncached permission path")
	})
}

func mtIdentity(role string) *authn.Identity {
	if role == "" {
		return &authn.Identity{}
	}
	return &authn.Identity{
		IDTokenClaims: &authnlib.Claims[authnlib.IDTokenClaims]{
			Rest: authnlib.IDTokenClaims{Role: role},
		},
	}
}

func TestRegistrationsProvider_ActionsForUser(t *testing.T) {
	provider := NewRegistrationsProvider([]accesscontrol.RoleRegistration{
		{
			Role: accesscontrol.RoleDTO{
				Name: "fixed:dashboards:reader",
				Permissions: []accesscontrol.Permission{
					{Action: "dashboards:read", Scope: "dashboards:*"},
				},
			},
			Grants: []string{"Viewer"},
		},
		{
			Role: accesscontrol.RoleDTO{
				Name: "fixed:dashboards:writer",
				Permissions: []accesscontrol.Permission{
					{Action: "dashboards:write", Scope: "dashboards:*"},
				},
			},
			Grants: []string{"Editor"},
		},
		{
			Role: accesscontrol.RoleDTO{
				Name: "fixed:users:writer",
				Permissions: []accesscontrol.Permission{
					{Action: "users:write"},
				},
			},
			Grants: []string{"Grafana Admin"},
		},
		{
			Role: accesscontrol.RoleDTO{
				Name: "fixed:excluded:reader",
				Permissions: []accesscontrol.Permission{
					{Action: "excluded:read"},
				},
			},
			Grants:  []string{"Viewer"},
			Exclude: []string{"Editor"},
		},
	})

	ctx := context.Background()

	t.Run("viewer grant is expanded to parent roles", func(t *testing.T) {
		actions, err := provider.ActionsForUser(ctx, mtIdentity("Admin"))
		require.NoError(t, err)
		require.True(t, actions["dashboards:read"], "viewer grant should reach Admin")
		require.True(t, actions["dashboards:write"], "editor grant should reach Admin")
	})

	t.Run("editor grant does not reach viewer", func(t *testing.T) {
		actions, err := provider.ActionsForUser(ctx, mtIdentity("Viewer"))
		require.NoError(t, err)
		require.True(t, actions["dashboards:read"])
		require.False(t, actions["dashboards:write"])
	})

	t.Run("excluded role does not inherit the grant", func(t *testing.T) {
		viewerActions, err := provider.ActionsForUser(ctx, mtIdentity("Viewer"))
		require.NoError(t, err)
		require.True(t, viewerActions["excluded:read"])

		editorActions, err := provider.ActionsForUser(ctx, mtIdentity("Editor"))
		require.NoError(t, err)
		require.False(t, editorActions["excluded:read"])
	})

	t.Run("grafana admin grant is not expanded to org roles", func(t *testing.T) {
		adminActions, err := provider.ActionsForUser(ctx, mtIdentity("Admin"))
		require.NoError(t, err)
		require.False(t, adminActions["users:write"])

		grafanaAdminActions, err := provider.ActionsForUser(ctx, mtIdentity("Grafana Admin"))
		require.NoError(t, err)
		require.True(t, grafanaAdminActions["users:write"])
	})

	t.Run("identity without id token claims gets empty set", func(t *testing.T) {
		actions, err := provider.ActionsForUser(ctx, mtIdentity(""))
		require.NoError(t, err)
		require.Empty(t, actions)
	})
}
