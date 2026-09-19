package licensing

import (
	"github.com/grafana/grafana/pkg/api/dtos"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/hooks"
	"github.com/grafana/grafana/pkg/services/navtree"
	"github.com/grafana/grafana/pkg/setting"
)

const (
	openSource = "Open Source"

	// FeatureDatasourcePermissions is the licensed feature name that gates
	// per-data-source permission enforcement. Enterprise answers it from the
	// license; OSS answers it from the rbac.datasource_permissions_enforcement
	// setting so the same two call sites keep working unchanged.
	FeatureDatasourcePermissions = "dspermissions.enforcement"
)

type OSSLicensingService struct {
	Cfg          *setting.Cfg
	HooksService *hooks.HooksService
}

func (*OSSLicensingService) Expiry() int64 {
	return 0
}

func (*OSSLicensingService) Edition() string {
	return openSource
}

func (*OSSLicensingService) StateInfo() string {
	return ""
}

func (*OSSLicensingService) ContentDeliveryPrefix() string {
	return "grafana-oss"
}

func (l *OSSLicensingService) LicenseURL(showAdminLicensingPage bool) string {
	if showAdminLicensingPage {
		return l.Cfg.AppSubURL + "/admin/upgrading"
	}

	return "https://grafana.com/oss/grafana?utm_source=grafana_footer"
}

func (l *OSSLicensingService) EnabledFeatures() map[string]bool {
	features := map[string]bool{}
	if l.datasourcePermissionsEnforced() {
		features[FeatureDatasourcePermissions] = true
	}
	return features
}

func (l *OSSLicensingService) FeatureEnabled(feature string) bool {
	return feature == FeatureDatasourcePermissions && l.datasourcePermissionsEnforced()
}

// Cfg is nil in a number of tests that construct OSSLicensingService directly.
func (l *OSSLicensingService) datasourcePermissionsEnforced() bool {
	return l.Cfg != nil && l.Cfg.RBAC.DatasourcePermissionsEnforcement
}

func ProvideService(cfg *setting.Cfg, hooksService *hooks.HooksService) *OSSLicensingService {
	l := &OSSLicensingService{
		Cfg:          cfg,
		HooksService: hooksService,
	}
	l.HooksService.AddIndexDataHook(func(indexData *dtos.IndexViewData, req *contextmodel.ReqContext) {
		if !req.IsGrafanaAdmin {
			return
		}

		if adminNode := indexData.NavTree.FindById(navtree.NavIDCfgGeneral); adminNode != nil {
			adminNode.Children = append(adminNode.Children, &navtree.NavLink{
				Text:       "Stats and license",
				Id:         "upgrading",
				Url:        l.LicenseURL(req.IsGrafanaAdmin),
				Icon:       "unlock",
				SortWeight: -1,
			})
		}
	})

	return l
}
