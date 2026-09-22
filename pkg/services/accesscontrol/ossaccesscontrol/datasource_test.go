package ossaccesscontrol_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/ossaccesscontrol"
	actestutil "github.com/grafana/grafana/pkg/services/accesscontrol/ossaccesscontrol/testutil"
	"github.com/grafana/grafana/pkg/services/datasources"
	datasourceservice "github.com/grafana/grafana/pkg/services/datasources/service"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/sqlstore"
	"github.com/grafana/grafana/pkg/services/team"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/util/testutil"
)

const testOrgID int64 = 1

func setupDatasourcePermissions(t *testing.T) (*ossaccesscontrol.DatasourcePermissionsService, *datasources.DataSource) {
	t.Helper()

	svc, _, ds := setupDatasourcePermissionsWithStore(t)
	return svc, ds
}

func setupDatasourcePermissionsWithStore(t *testing.T) (*ossaccesscontrol.DatasourcePermissionsService, *sqlstore.SQLStore, *datasources.DataSource) {
	t.Helper()

	sqlStore, cfg := sqlstore.InitTestDB(t)
	features := featuremgmt.WithFeatures()

	svc, err := actestutil.ProvideDatasourcePermissions(features, cfg, sqlStore)
	require.NoError(t, err)

	store := datasourceservice.CreateStore(sqlStore, log.New("datasource-permissions-test"))
	ds, err := store.AddDataSource(context.Background(), &datasources.AddDataSourceCommand{
		OrgID:  testOrgID,
		Name:   "clickhouse",
		Type:   "grafana-clickhouse-datasource",
		Access: datasources.DS_ACCESS_PROXY,
		URL:    "http://localhost:8123",
	})
	require.NoError(t, err)

	return svc, sqlStore, ds
}

func permissionReader() *user.SignedInUser {
	return &user.SignedInUser{
		OrgID: testOrgID,
		Permissions: map[int64]map[string][]string{testOrgID: {
			datasources.ActionPermissionsRead: {"datasources:*"},
		}},
	}
}

func setupDatasourcePermissionsEnv(t *testing.T) (*actestutil.DatasourcePermissionsEnv, *sqlstore.SQLStore, *datasources.DataSource) {
	t.Helper()

	sqlStore, cfg := sqlstore.InitTestDB(t)
	// Each grant is read back immediately, so the permission cache would hide the
	// very transitions under test.
	cfg.RBAC.PermissionCache = false

	env, err := actestutil.ProvideDatasourcePermissionsEnv(featuremgmt.WithFeatures(), cfg, sqlStore)
	require.NoError(t, err)

	store := datasourceservice.CreateStore(sqlStore, log.New("datasource-permissions-test"))
	ds, err := store.AddDataSource(context.Background(), &datasources.AddDataSourceCommand{
		OrgID:  testOrgID,
		Name:   "clickhouse",
		Type:   "grafana-clickhouse-datasource",
		Access: datasources.DS_ACCESS_PROXY,
		URL:    "http://localhost:8123",
	})
	require.NoError(t, err)

	return env, sqlStore, ds
}

func setTeamMembership(t *testing.T, sqlStore *sqlstore.SQLStore, teamID, userID int64, member bool) {
	t.Helper()

	err := sqlStore.WithDbSession(context.Background(), func(sess *db.Session) error {
		if !member {
			_, err := sess.Exec("DELETE FROM team_member WHERE org_id = ? AND team_id = ? AND user_id = ?",
				testOrgID, teamID, userID)
			return err
		}
		now := time.Now()
		_, err := sess.Exec(
			"INSERT INTO team_member (org_id, team_id, user_id, permission, created, updated) VALUES (?, ?, ?, ?, ?, ?)",
			testOrgID, teamID, userID, 0, now, now)
		return err
	})
	require.NoError(t, err)
}

// queryScopes resolves the data source scopes a user may query. Team IDs are read
// back from the store rather than asserted onto the user, so that membership is
// what the assertion actually depends on.
func queryScopes(t *testing.T, env *actestutil.DatasourcePermissionsEnv, userID int64) []string {
	t.Helper()
	ctx := context.Background()

	teamIDs, _, err := env.TeamService.GetTeamIDsByUser(ctx, &team.GetTeamIDsByUserQuery{OrgID: testOrgID, UserID: userID})
	require.NoError(t, err)

	perms, err := env.AccessControl.GetUserPermissions(ctx,
		&user.SignedInUser{UserID: userID, OrgID: testOrgID, TeamIDs: teamIDs},
		accesscontrol.Options{},
	)
	require.NoError(t, err)

	scopes := []string{}
	for _, p := range perms {
		if p.Action == datasources.ActionQuery {
			scopes = append(scopes, p.Scope)
		}
	}
	return scopes
}

func createUser(t *testing.T, env *actestutil.DatasourcePermissionsEnv, login string) *user.User {
	t.Helper()

	u, err := env.UserService.Create(context.Background(), &user.CreateUserCommand{
		Login: login,
		OrgID: testOrgID,
	})
	require.NoError(t, err)
	return u
}

func TestIntegrationDatasourcePermissionsService(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	t.Run("Query maps to read and query", func(t *testing.T) {
		svc, ds := setupDatasourcePermissions(t)

		got, err := svc.SetBuiltInRolePermission(context.Background(), testOrgID, "Viewer", ds.UID, "Query")
		require.NoError(t, err)

		assert.Subset(t, got.Actions, ossaccesscontrol.DatasourceQueryActions)
		assert.NotContains(t, got.Actions, datasources.ActionWrite)
	})

	t.Run("Admin maps to the permission management actions", func(t *testing.T) {
		svc, ds := setupDatasourcePermissions(t)

		got, err := svc.SetBuiltInRolePermission(context.Background(), testOrgID, "Editor", ds.UID, "Admin")
		require.NoError(t, err)

		assert.Subset(t, got.Actions, []string{
			datasources.ActionWrite,
			datasources.ActionDelete,
			datasources.ActionPermissionsRead,
			datasources.ActionPermissionsWrite,
		})
	})

	t.Run("an empty permission removes the assignment", func(t *testing.T) {
		svc, ds := setupDatasourcePermissions(t)
		ctx := context.Background()

		_, err := svc.SetBuiltInRolePermission(ctx, testOrgID, "Viewer", ds.UID, "Query")
		require.NoError(t, err)

		_, err = svc.SetBuiltInRolePermission(ctx, testOrgID, "Viewer", ds.UID, "")
		require.NoError(t, err)

		perms, err := svc.GetPermissions(ctx, permissionReader(), ds.UID)
		require.NoError(t, err)
		for _, p := range perms {
			assert.NotEqual(t, "Viewer", p.BuiltInRole)
		}
	})

	t.Run("the seeding call made at data source creation succeeds", func(t *testing.T) {
		svc, ds := setupDatasourcePermissions(t)

		_, err := svc.SetPermissions(context.Background(), testOrgID, ds.UID,
			accesscontrol.SetResourcePermissionCommand{BuiltinRole: "Viewer", Permission: "Query"},
			accesscontrol.SetResourcePermissionCommand{BuiltinRole: "Editor", Permission: "Query"},
		)
		require.NoError(t, err)
	})

	// AddDataSource seeds managed permissions from inside its own transaction, so
	// the resource validator must see the row the same transaction just wrote.
	t.Run("seeding works from inside an open transaction", func(t *testing.T) {
		svc, sqlStore, _ := setupDatasourcePermissionsWithStore(t)
		store := datasourceservice.CreateStore(sqlStore, log.New("datasource-permissions-test"))

		err := sqlStore.InTransaction(context.Background(), func(ctx context.Context) error {
			ds, err := store.AddDataSource(ctx, &datasources.AddDataSourceCommand{
				OrgID:  testOrgID,
				Name:   "in-transaction",
				Type:   "grafana-clickhouse-datasource",
				Access: datasources.DS_ACCESS_PROXY,
				URL:    "http://localhost:8123",
			})
			if err != nil {
				return err
			}

			_, err = svc.SetPermissions(ctx, testOrgID, ds.UID,
				accesscontrol.SetResourcePermissionCommand{BuiltinRole: "Viewer", Permission: "Query"},
			)
			return err
		})
		require.NoError(t, err)
	})

	// Unlike the previous OSS stub, the real service validates the assignee. A
	// creator whose user cannot be resolved now fails data source creation.
	t.Run("an unresolvable creator is rejected", func(t *testing.T) {
		svc, ds := setupDatasourcePermissions(t)

		_, err := svc.SetPermissions(context.Background(), testOrgID, ds.UID,
			accesscontrol.SetResourcePermissionCommand{UserID: 12345, Permission: "Admin"},
		)
		assert.Error(t, err)
	})

	t.Run("an unknown data source is rejected", func(t *testing.T) {
		svc, _ := setupDatasourcePermissions(t)

		_, err := svc.SetBuiltInRolePermission(context.Background(), testOrgID, "Viewer", "does-not-exist", "Query")
		assert.Error(t, err)
	})

	t.Run("an unknown permission level is rejected", func(t *testing.T) {
		svc, ds := setupDatasourcePermissions(t)

		_, err := svc.SetBuiltInRolePermission(context.Background(), testOrgID, "Viewer", ds.UID, "View")
		assert.Error(t, err)
	})

	// Teams are the intended production grant mechanism: the rollout restricts a
	// data source by deleting its seeded built-in grants and granting a team
	// instead. Nothing else in this package covers that path.
	t.Run("a team grant follows team membership", func(t *testing.T) {
		env, sqlStore, ds := setupDatasourcePermissionsEnv(t)
		ctx := context.Background()
		scope := datasources.ScopeProvider.GetResourceScopeUID(ds.UID)

		member := createUser(t, env, "member")
		outsider := createUser(t, env, "outsider")

		tm, err := env.TeamService.CreateTeam(ctx, &team.CreateTeamCommand{Name: "rbac-team", OrgID: testOrgID})
		require.NoError(t, err)
		setTeamMembership(t, sqlStore, tm.ID, member.ID, true)

		_, err = env.Permissions.SetTeamPermission(ctx, testOrgID, tm.ID, ds.UID, "Query")
		require.NoError(t, err)

		assert.Contains(t, queryScopes(t, env, member.ID), scope,
			"a team member should inherit the team's Query grant")
		assert.NotContains(t, queryScopes(t, env, outsider.ID), scope,
			"a non-member should not inherit it")

		setTeamMembership(t, sqlStore, tm.ID, member.ID, false)

		assert.NotContains(t, queryScopes(t, env, member.ID), scope,
			"removing the membership should revoke the inherited grant")
		assert.NotContains(t, queryScopes(t, env, outsider.ID), scope)
	})
}
