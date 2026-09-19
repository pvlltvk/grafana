package guardian

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
)

func userWithScopes(action string, scopes ...string) identity.Requester {
	return &user.SignedInUser{
		OrgID:       1,
		Permissions: map[int64]map[string][]string{1: {action: scopes}},
	}
}

func TestRBACGuardian_CanQuery(t *testing.T) {
	ds := datasources.DataSource{ID: 3, UID: "ds-uid", OrgID: 1}

	tests := []struct {
		name     string
		user     identity.Requester
		expected bool
	}{
		{
			name:     "exact uid scope is allowed",
			user:     userWithScopes(datasources.ActionQuery, "datasources:uid:ds-uid"),
			expected: true,
		},
		{
			name:     "uid wildcard is allowed",
			user:     userWithScopes(datasources.ActionQuery, "datasources:uid:*"),
			expected: true,
		},
		{
			name:     "resource wildcard is allowed",
			user:     userWithScopes(datasources.ActionQuery, "datasources:*"),
			expected: true,
		},
		{
			name:     "global wildcard is allowed",
			user:     userWithScopes(datasources.ActionQuery, "*"),
			expected: true,
		},
		{
			name:     "another data source is denied",
			user:     userWithScopes(datasources.ActionQuery, "datasources:uid:other"),
			expected: false,
		},
		{
			name:     "read permission alone does not grant query",
			user:     userWithScopes(datasources.ActionRead, "datasources:uid:ds-uid"),
			expected: false,
		},
		{
			name:     "no permissions at all is denied",
			user:     &user.SignedInUser{OrgID: 1},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := newRBACGuardian(tt.user, ds)
			got, err := g.CanQuery(ds.ID)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, got)
		})
	}

	t.Run("an id the caller did not resolve is denied", func(t *testing.T) {
		g := newRBACGuardian(userWithScopes(datasources.ActionQuery, "*"), ds)
		got, err := g.CanQuery(ds.ID + 1)
		require.NoError(t, err)
		assert.False(t, got)
	})
}

func TestRBACGuardian_Filter(t *testing.T) {
	all := []*datasources.DataSource{
		{ID: 1, UID: "one", OrgID: 1},
		{ID: 2, UID: "two", OrgID: 1},
		{ID: 3, UID: "three", OrgID: 1},
	}

	t.Run("read filter keeps only readable data sources", func(t *testing.T) {
		g := newRBACGuardian(userWithScopes(datasources.ActionRead, "datasources:uid:one", "datasources:uid:three"))

		filtered, err := g.FilterDatasourcesByReadPermissions(all)
		require.NoError(t, err)

		require.Len(t, filtered, 2)
		assert.Equal(t, "one", filtered[0].UID)
		assert.Equal(t, "three", filtered[1].UID)
	})

	t.Run("query filter is independent of read", func(t *testing.T) {
		g := newRBACGuardian(userWithScopes(datasources.ActionQuery, "datasources:uid:two"))

		filtered, err := g.FilterDatasourcesByQueryPermissions(all)
		require.NoError(t, err)

		require.Len(t, filtered, 1)
		assert.Equal(t, "two", filtered[0].UID)
	})

	t.Run("wildcard keeps everything", func(t *testing.T) {
		g := newRBACGuardian(userWithScopes(datasources.ActionRead, "datasources:*"))

		filtered, err := g.FilterDatasourcesByReadPermissions(all)
		require.NoError(t, err)
		assert.Len(t, filtered, len(all))
	})

	t.Run("no permissions filters everything out", func(t *testing.T) {
		g := newRBACGuardian(&user.SignedInUser{OrgID: 1})

		filtered, err := g.FilterDatasourcesByReadPermissions(all)
		require.NoError(t, err)
		assert.Empty(t, filtered)
	})
}

func TestProvideGuardian(t *testing.T) {
	ds := datasources.DataSource{ID: 1, UID: "one", OrgID: 1}
	denied := &user.SignedInUser{OrgID: 1}

	t.Run("allows everything while enforcement is off", func(t *testing.T) {
		p := ProvideGuardian(setting.NewCfg())

		g := p.New(1, denied, ds)
		assert.IsType(t, &AllowGuardian{}, g)

		can, err := g.CanQuery(ds.ID)
		require.NoError(t, err)
		assert.True(t, can)
	})

	t.Run("enforces once the setting is on", func(t *testing.T) {
		cfg := setting.NewCfg()
		cfg.RBAC.DatasourcePermissionsEnforcement = true
		p := ProvideGuardian(cfg)

		g := p.New(1, denied, ds)
		assert.IsType(t, &RBACGuardian{}, g)

		can, err := g.CanQuery(ds.ID)
		require.NoError(t, err)
		assert.False(t, can)
	})
}
