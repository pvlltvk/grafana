package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/localcache"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/datasources/guardian"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util/testutil"
)

func enforcingGuardian() guardian.DatasourceGuardianProvider {
	cfg := setting.NewCfg()
	cfg.RBAC.DatasourcePermissionsEnforcement = true
	return guardian.ProvideGuardian(cfg)
}

func queryUser(scopes ...string) *user.SignedInUser {
	return &user.SignedInUser{
		OrgID: 1,
		Permissions: map[int64]map[string][]string{1: {
			datasources.ActionQuery: scopes,
		}},
	}
}

// The SQL store is never reached on these paths, so a nil db is enough.
func newCachedService(t *testing.T, ds *datasources.DataSource) *CacheServiceImpl {
	t.Helper()

	cache := localcache.New(5*time.Second, 5*time.Second)
	cache.Set(uidKey(ds.OrgID, ds.UID), ds, time.Minute)
	cache.Set(idKey(ds.ID), ds, time.Minute)

	return ProvideCacheService(cache, nil, enforcingGuardian())
}

func TestCacheServiceGuardsCachedDatasources(t *testing.T) {
	ds := &datasources.DataSource{ID: 7, UID: "ds-uid", OrgID: 1}

	t.Run("GetDatasourceByUID denies a user without query permission", func(t *testing.T) {
		svc := newCachedService(t, ds)

		_, err := svc.GetDatasourceByUID(context.Background(), ds.UID, queryUser("datasources:uid:other"), false)
		assert.ErrorIs(t, err, datasources.ErrDataSourceAccessDenied)
	})

	t.Run("GetDatasourceByUID allows a user with query permission", func(t *testing.T) {
		svc := newCachedService(t, ds)

		got, err := svc.GetDatasourceByUID(context.Background(), ds.UID, queryUser("datasources:uid:ds-uid"), false)
		require.NoError(t, err)
		assert.Equal(t, ds.UID, got.UID)
	})

	t.Run("GetDatasource denies a user without query permission", func(t *testing.T) {
		svc := newCachedService(t, ds)

		_, err := svc.GetDatasource(context.Background(), ds.ID, queryUser("datasources:uid:other"), false)
		assert.ErrorIs(t, err, datasources.ErrDataSourceAccessDenied)
	})

	t.Run("a cache entry populated by one user is not served to another", func(t *testing.T) {
		svc := newCachedService(t, ds)

		_, err := svc.GetDatasourceByUID(context.Background(), ds.UID, queryUser("datasources:uid:ds-uid"), false)
		require.NoError(t, err)

		_, err = svc.GetDatasourceByUID(context.Background(), ds.UID, queryUser(), false)
		assert.ErrorIs(t, err, datasources.ErrDataSourceAccessDenied)
	})
}

func TestIntegrationCacheServiceGuardsUncachedDatasources(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	sqlStore := db.InitTestDB(t)
	store := SqlStore{db: sqlStore, logger: log.New("datasources")}

	ds, err := store.AddDataSource(context.Background(), &datasources.AddDataSourceCommand{
		OrgID:  1,
		Name:   "guarded",
		Type:   datasources.DS_GRAPHITE,
		Access: datasources.DS_ACCESS_DIRECT,
		URL:    "http://test",
	})
	require.NoError(t, err)

	svc := ProvideCacheService(localcache.New(5*time.Second, 5*time.Second), sqlStore, enforcingGuardian())

	t.Run("denies on the store path", func(t *testing.T) {
		_, err := svc.GetDatasourceByUID(context.Background(), ds.UID, queryUser(), true)
		assert.ErrorIs(t, err, datasources.ErrDataSourceAccessDenied)
	})

	t.Run("allows on the store path", func(t *testing.T) {
		got, err := svc.GetDatasourceByUID(context.Background(), ds.UID, queryUser("datasources:uid:"+ds.UID), true)
		require.NoError(t, err)
		assert.Equal(t, ds.UID, got.UID)
	})
}
