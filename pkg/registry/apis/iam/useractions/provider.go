package useractions

import (
	"context"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/seeding"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/user"
)

// RolePermissionProvider resolves the RBAC actions granted to the calling
// identity by its basic role (Viewer, Editor, Admin, None, plus Grafana
// Admin in single-tenant) — never by per-user, team or managed-role
// assignments.
type RolePermissionProvider interface {
	ActionsForUser(ctx context.Context, requester identity.Requester) (map[string]bool, error)
}

type userPermissionsProvider struct {
	ac accesscontrol.Service
}

// NewUserPermissionsProvider resolves role actions through the access control
// service using a synthetic requester that carries only the caller's org,
// basic role and server-admin flag. With no user id and no teams, both the
// OSS and the enterprise implementation take the uncached path and return
// only role-derived permissions, from wherever the running edition keeps
// them: the in-memory role registry in OSS, the seeded (and admin-editable)
// database roles under enterprise access-control enforcement. Used in
// single-tenant mode.
func NewUserPermissionsProvider(ac accesscontrol.Service) RolePermissionProvider {
	return &userPermissionsProvider{ac: ac}
}

func (p *userPermissionsProvider) ActionsForUser(ctx context.Context, requester identity.Requester) (map[string]bool, error) {
	synthetic := &user.SignedInUser{
		OrgID:          requester.GetOrgID(),
		OrgRole:        requester.GetOrgRole(),
		IsGrafanaAdmin: requester.GetIsGrafanaAdmin(),
	}

	permissions, err := p.ac.GetUserPermissions(ctx, synthetic, accesscontrol.Options{})
	if err != nil {
		return nil, err
	}
	return accesscontrol.BuildPermissionsMap(permissions), nil
}

type registrationsProvider struct {
	actionsByRole map[string]map[string]bool
}

// NewRegistrationsProvider resolves role actions from a set of fixed-role
// registrations, expanding grants up the basic role hierarchy (a grant to
// Viewer is also granted to Editor and Admin). Used in multi-tenant mode,
// where no access control service runs and the registration list is the
// service-independent source of truth. The basic role is read from the
// verified ID token claims: the multi-tenant authenticator never sets
// OrgRoles (GetOrgRole always returns None there), and identities without
// an ID token (pure service and on-behalf-of calls) have no role and get an
// empty permission set.
func NewRegistrationsProvider(registrations []accesscontrol.RoleRegistration) RolePermissionProvider {
	logger := log.New("iam.useractions")

	desired := make(map[accesscontrol.SeedPermission]struct{})
	for i := range registrations {
		seeding.AppendDesiredPermissions(desired, logger, &registrations[i].Role, registrations[i].Grants, registrations[i].Exclude)
	}

	actionsByRole := make(map[string]map[string]bool)
	for sp := range desired {
		if actionsByRole[sp.BuiltInRole] == nil {
			actionsByRole[sp.BuiltInRole] = make(map[string]bool)
		}
		actionsByRole[sp.BuiltInRole][sp.Action] = true
	}

	return &registrationsProvider{actionsByRole: actionsByRole}
}

func (p *registrationsProvider) ActionsForUser(_ context.Context, requester identity.Requester) (map[string]bool, error) {
	actions := make(map[string]bool)
	for action := range p.actionsByRole[roleFromIDTokenClaims(requester)] {
		actions[action] = true
	}
	return actions, nil
}

// roleFromIDTokenClaims extracts the basic role from the verified ID token
// claims attached to the identity by the multi-tenant authenticator. Returns
// an empty string when the identity carries no ID token claims.
func roleFromIDTokenClaims(requester identity.Requester) string {
	ident, ok := requester.(*authn.Identity)
	if !ok || ident.IDTokenClaims == nil {
		return ""
	}
	return ident.IDTokenClaims.Rest.Role
}
