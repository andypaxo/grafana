package useractions

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/tests/apis"
	"github.com/grafana/grafana/pkg/tests/testinfra"
	"github.com/grafana/grafana/pkg/tests/testsuite"
	"github.com/grafana/grafana/pkg/util/testutil"
)

func TestMain(m *testing.M) {
	testsuite.Run(m)
}

const routePath = "/apis/iam.grafana.app/v0alpha1/namespaces/default/userActions"

func TestIntegrationUserActions(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	helper := apis.NewK8sTestHelper(t, testinfra.GrafanaOpts{
		AppModeProduction: false,
		DisableAnonymous:  true,
		EnableFeatureToggles: []string{
			featuremgmt.FlagGrafanaAPIServerWithExperimentalAPIs,
		},
	})
	t.Cleanup(helper.Shutdown)

	getUserActions := func(t *testing.T, user apis.User) map[string]bool {
		t.Helper()
		res := map[string]bool{}
		rsp := apis.DoRequest(helper, apis.RequestParams{
			User: user,
			Path: routePath,
		}, &res)
		require.Equal(t, 200, rsp.Response.StatusCode)
		return res
	}

	t.Run("viewer gets read but not write actions", func(t *testing.T) {
		actions := getUserActions(t, helper.Org1.Viewer)
		require.True(t, actions["annotations:read"])
		require.False(t, actions["dashboards:create"])
		require.False(t, actions["teams:create"])
	})

	t.Run("editor gets editor actions", func(t *testing.T) {
		actions := getUserActions(t, helper.Org1.Editor)
		require.True(t, actions["annotations:read"])
		require.True(t, actions["dashboards:create"])
		require.True(t, actions["alert.instances:create"])
		require.False(t, actions["teams:create"])
	})

	t.Run("admin gets admin actions", func(t *testing.T) {
		actions := getUserActions(t, helper.Org1.Admin)
		require.True(t, actions["dashboards:create"])
		require.True(t, actions["teams:create"])
	})

	// The provider resolves permissions through GetUserPermissions with a
	// synthetic role-only requester, which covers the same role-derived
	// sources as the legacy endpoint (role registry, seeded builtin grants,
	// shared-with-me) but intentionally omits per-user and team assignments.
	// The viewer has neither, so the two endpoints must match exactly; admin
	// and editor are members of the helper's Staff team, so for them the
	// legacy response is a superset.
	getLegacyActions := func(t *testing.T, user apis.User) map[string]bool {
		t.Helper()
		legacy := map[string]bool{}
		rsp := apis.DoRequest(helper, apis.RequestParams{
			User: user,
			Path: "/api/access-control/user/actions",
		}, &legacy)
		require.Equal(t, 200, rsp.Response.StatusCode)
		return legacy
	}

	t.Run("exact parity with legacy endpoint for a user without team or user assignments", func(t *testing.T) {
		require.Equal(t, getLegacyActions(t, helper.Org1.Viewer), getUserActions(t, helper.Org1.Viewer))
	})

	t.Run("subset of legacy endpoint for team members", func(t *testing.T) {
		for name, user := range map[string]apis.User{
			"editor": helper.Org1.Editor,
			"admin":  helper.Org1.Admin,
		} {
			t.Run(name, func(t *testing.T) {
				legacy := getLegacyActions(t, user)
				actions := getUserActions(t, user)
				require.NotEmpty(t, actions)
				for action := range actions {
					require.Contains(t, legacy, action)
				}
			})
		}
	})

	t.Run("unauthenticated is rejected", func(t *testing.T) {
		res := map[string]any{}
		rsp := apis.DoRequest(helper, apis.RequestParams{
			Path: routePath,
		}, &res)
		require.Equal(t, 401, rsp.Response.StatusCode)
	})
}
