package guardian

import (
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/setting"
)

type DatasourceGuardianProvider interface {
	New(orgID int64, user identity.Requester, dataSources ...datasources.DataSource) DatasourceGuardian
}

type DatasourceGuardian interface {
	CanQuery(datasourceID int64) (bool, error)
	FilterDatasourcesByReadPermissions([]*datasources.DataSource) ([]*datasources.DataSource, error)
	FilterDatasourcesByQueryPermissions([]*datasources.DataSource) ([]*datasources.DataSource, error)
}

func ProvideGuardian(cfg *setting.Cfg) *OSSProvider {
	return &OSSProvider{enforced: cfg != nil && cfg.RBAC.DatasourcePermissionsEnforcement}
}

type OSSProvider struct {
	enforced bool
}

func (p *OSSProvider) New(orgID int64, user identity.Requester, dataSources ...datasources.DataSource) DatasourceGuardian {
	if !p.enforced {
		return &AllowGuardian{}
	}
	return newRBACGuardian(user, dataSources...)
}
