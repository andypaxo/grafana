package useractions

import (
	"context"
	"fmt"

	claims "github.com/grafana/authlib/types"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/registry/apis/iam/common"
	"github.com/grafana/grafana/pkg/registry/apis/iam/legacy"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/apiserver/endpoints/request"
	authzstore "github.com/grafana/grafana/pkg/services/authz/rbac/store"
)

// teamPageSize bounds each page of the team lookup, mirroring the authz
// service's team resolution.
const teamPageSize = 50

// RolePermissionProvider resolves the RBAC actions granted to the calling
// identity.
type RolePermissionProvider interface {
	ActionsForUser(ctx context.Context, requester identity.Requester) (map[string]bool, error)
}

// identityStore is the subset of the IAM legacy store needed to resolve the
// teams an identity belongs to.
type identityStore interface {
	ListUserTeams(ctx context.Context, ns claims.NamespaceInfo, query legacy.ListUserTeamsQuery) (*legacy.ListUserTeamsResult, error)
}

// identifierStore resolves an identity's internal id and its basic role.
type identifierStore interface {
	GetUserIdentifiers(ctx context.Context, query authzstore.UserIdentifierQuery) (*authzstore.UserIdentifiers, error)
	GetBasicRoles(ctx context.Context, ns claims.NamespaceInfo, query authzstore.BasicRoleQuery) (*authzstore.BasicRole, error)
}

type sqlProvider struct {
	actions        ActionStore
	identifiers    identifierStore
	identities     identityStore
	actionResolver accesscontrol.ActionResolver
}

// NewSQLProvider resolves the caller's actions from the RBAC tables of the
// tenant database: permissions granted through its basic role (including
// Grafana Admin for server admins), roles assigned directly to the user, and
// roles assigned to its teams. Everything is keyed off the request namespace,
// so one implementation serves both single-tenant Grafana and the multi-tenant
// IAM apiserver.
//
// actionResolver expands action set permissions (for example dashboards:view)
// into the individual actions they stand for. It may be nil where no action
// sets are registered, in which case action sets are reported as-is.
func NewSQLProvider(actions ActionStore, identifiers identifierStore, identities identityStore, actionResolver accesscontrol.ActionResolver) RolePermissionProvider {
	return &sqlProvider{
		actions:        actions,
		identifiers:    identifiers,
		identities:     identities,
		actionResolver: actionResolver,
	}
}

func (p *sqlProvider) ActionsForUser(ctx context.Context, requester identity.Requester) (map[string]bool, error) {
	// Only users and service accounts hold RBAC assignments. Anonymous
	// identities and access policies get an empty set rather than an error,
	// matching the legacy endpoint's behaviour for identities without
	// permissions.
	if !requester.IsIdentityType(claims.TypeUser, claims.TypeServiceAccount) {
		return map[string]bool{}, nil
	}

	// Take the namespace from the request rather than the identity: it is the
	// tenant the caller asked about, it has already been checked by the
	// namespace authorizer, and it is what the org id was resolved from.
	ns, err := request.NamespaceInfoFrom(ctx, true)
	if err != nil {
		return nil, err
	}

	ids, err := p.identifiers.GetUserIdentifiers(ctx, authzstore.UserIdentifierQuery{UserUID: requester.GetIdentifier()})
	if err != nil {
		return nil, fmt.Errorf("could not resolve identity: %w", err)
	}

	basicRole, err := p.identifiers.GetBasicRoles(ctx, ns, authzstore.BasicRoleQuery{UserID: ids.ID})
	if err != nil {
		return nil, fmt.Errorf("could not resolve basic role: %w", err)
	}

	teamIDs, err := p.userTeams(ctx, ns, ids.UID)
	if err != nil {
		return nil, err
	}

	actions, err := p.actions.GetUserActions(ctx, ns, ActionsQuery{
		UserID:        ids.ID,
		TeamIDs:       teamIDs,
		Role:          basicRole.Role,
		IsServerAdmin: basicRole.IsAdmin,
	})
	if err != nil {
		return nil, fmt.Errorf("could not resolve actions: %w", err)
	}

	return p.buildActionMap(actions), nil
}

func (p *sqlProvider) userTeams(ctx context.Context, ns claims.NamespaceInfo, userUID string) ([]int64, error) {
	var teamIDs []int64
	query := legacy.ListUserTeamsQuery{
		UserUID:    userUID,
		Pagination: common.Pagination{Limit: teamPageSize},
	}

	for {
		teams, err := p.identities.ListUserTeams(ctx, ns, query)
		if err != nil {
			return nil, fmt.Errorf("could not resolve teams: %w", err)
		}
		for _, team := range teams.Items {
			teamIDs = append(teamIDs, team.ID)
		}
		if teams.Continue == 0 {
			return teamIDs, nil
		}
		query.Pagination.Continue = teams.Continue
	}
}

// buildActionMap turns the action rows into the action -> true map the
// endpoint returns, expanding action sets when a resolver is configured.
func (p *sqlProvider) buildActionMap(actions []string) map[string]bool {
	if p.actionResolver == nil {
		out := make(map[string]bool, len(actions))
		for _, action := range actions {
			out[action] = true
		}
		return out
	}

	permissions := make([]accesscontrol.Permission, 0, len(actions))
	for _, action := range actions {
		permissions = append(permissions, accesscontrol.Permission{Action: action})
	}
	return accesscontrol.BuildPermissionsMap(p.actionResolver.ExpandActionSets(permissions))
}
