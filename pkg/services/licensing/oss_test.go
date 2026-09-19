package licensing

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/grafana/grafana/pkg/setting"
)

func TestOSSLicensingServiceDatasourcePermissions(t *testing.T) {
	t.Run("is off by default", func(t *testing.T) {
		l := &OSSLicensingService{Cfg: setting.NewCfg()}

		assert.False(t, l.FeatureEnabled(FeatureDatasourcePermissions))
		assert.Empty(t, l.EnabledFeatures())
	})

	t.Run("follows the rbac setting", func(t *testing.T) {
		cfg := setting.NewCfg()
		cfg.RBAC.DatasourcePermissionsEnforcement = true
		l := &OSSLicensingService{Cfg: cfg}

		assert.True(t, l.FeatureEnabled(FeatureDatasourcePermissions))
		assert.Equal(t, map[string]bool{FeatureDatasourcePermissions: true}, l.EnabledFeatures())
	})

	t.Run("no other feature is ever enabled", func(t *testing.T) {
		cfg := setting.NewCfg()
		cfg.RBAC.DatasourcePermissionsEnforcement = true
		l := &OSSLicensingService{Cfg: cfg}

		assert.False(t, l.FeatureEnabled("analytics"))
		assert.False(t, l.FeatureEnabled("caching"))
	})

	t.Run("a nil Cfg does not panic", func(t *testing.T) {
		l := &OSSLicensingService{}

		assert.False(t, l.FeatureEnabled(FeatureDatasourcePermissions))
		assert.Empty(t, l.EnabledFeatures())
	})
}
