package ossaccesscontrol_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/ossaccesscontrol"
	actestutil "github.com/grafana/grafana/pkg/services/accesscontrol/ossaccesscontrol/testutil"
	"github.com/grafana/grafana/pkg/services/datasources"
	datasourceservice "github.com/grafana/grafana/pkg/services/datasources/service"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/sqlstore"
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
}
