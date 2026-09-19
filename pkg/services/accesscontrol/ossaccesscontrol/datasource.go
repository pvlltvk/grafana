package ossaccesscontrol

import (
	"context"
	"slices"

	"go.opentelemetry.io/otel"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/resourcepermissions"
	"github.com/grafana/grafana/pkg/services/datasources"
	datasourceservice "github.com/grafana/grafana/pkg/services/datasources/service"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/licensing"
	"github.com/grafana/grafana/pkg/services/serviceaccounts"
	"github.com/grafana/grafana/pkg/services/team"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
)

var tracer = otel.Tracer("github.com/grafana/grafana/pkg/accesscontrol/ossaccesscontrol")

// DatasourceQueryActions contains permissions to read information
// about a data source and submit arbitrary queries to it.
var DatasourceQueryActions = []string{
	datasources.ActionRead,
	datasources.ActionQuery,
}

var DatasourceEditActions = slices.Concat(DatasourceQueryActions, []string{
	datasources.ActionWrite,
})

var DatasourceAdminActions = slices.Concat(DatasourceEditActions, []string{
	datasources.ActionDelete,
	datasources.ActionPermissionsRead,
	datasources.ActionPermissionsWrite,
})

type DatasourcePermissionsService struct {
	*resourcepermissions.Service
}

var _ accesscontrol.DatasourcePermissionsService = new(DatasourcePermissionsService)

// DatasourcePermissionsRoleRegistrations returns the templated reader/writer fixed
// roles for data source resource permissions (fixed:datasources.permissions:reader
// and :writer). These mirror the roles declared by ProvideDatasourcePermissionsService
// through resourcepermissions.New; the identity fields below must match the Options
// passed there.
func DatasourcePermissionsRoleRegistrations() []accesscontrol.RoleRegistration {
	return resourcepermissions.FixedRoleRegistrations(resourcepermissions.Options{
		Resource:       datasourcePermissionsResource,
		ReaderRoleName: permissionReaderRoleName,
		WriterRoleName: permissionWriterRoleName,
		RoleGroup:      datasourcePermissionsRoleGroup,
	})
}

func ProvideDatasourcePermissionsService(
	cfg *setting.Cfg, features featuremgmt.FeatureToggles, router routing.RouteRegister, sql db.DB,
	ac accesscontrol.AccessControl, license licensing.Licensing, retriever datasourceservice.DataSourceRetriever,
	service accesscontrol.Service, teamService team.Service, userService user.Service,
	serviceAccountRetriever serviceaccounts.ServiceAccountRetriever,
	actionSetService resourcepermissions.ActionSetService,
) (*DatasourcePermissionsService, error) {
	// DataSourceRetriever reads straight from the store, so no identity is needed;
	// it is also the one data source dependency that does not cycle back into the
	// data source service through DatasourcePermissionsService.
	getDataSource := func(ctx context.Context, orgID int64, resourceID string) (*datasources.DataSource, error) {
		return retriever.GetDataSource(ctx, &datasources.GetDataSourceQuery{
			OrgID: orgID,
			UID:   resourceID,
		})
	}

	options := resourcepermissions.Options{
		// APIGroup and RestConfigProvider are deliberately unset: data sources
		// resolve a per-plugin API group at request time, and requiresAPIGroup
		// exempts them from the Kubernetes resource-permission redirect.
		Resource:          datasourcePermissionsResource,
		ResourceAttribute: "uid",
		ResourceValidator: func(ctx context.Context, orgID int64, resourceID string) error {
			ctx, span := tracer.Start(ctx, "accesscontrol.ossaccesscontrol.ProvideDatasourcePermissionsService.ResourceValidator")
			defer span.End()

			_, err := getDataSource(ctx, orgID, resourceID)
			return err
		},
		DatasourceTypeResolver: func(ctx context.Context, orgID int64, resourceID string) (string, error) {
			ctx, span := tracer.Start(ctx, "accesscontrol.ossaccesscontrol.ProvideDatasourcePermissionsService.DatasourceTypeResolver")
			defer span.End()

			ds, err := getDataSource(ctx, orgID, resourceID)
			if err != nil {
				return "", err
			}
			return ds.Type, nil
		},
		Assignments: resourcepermissions.Assignments{
			Users:           true,
			Teams:           true,
			BuiltInRoles:    true,
			ServiceAccounts: true,
		},
		PermissionsToActions: map[string][]string{
			"Query": DatasourceQueryActions,
			"Edit":  DatasourceEditActions,
			"Admin": DatasourceAdminActions,
		},
		ReaderRoleName: permissionReaderRoleName,
		WriterRoleName: permissionWriterRoleName,
		RoleGroup:      datasourcePermissionsRoleGroup,
	}

	srv, err := resourcepermissions.New(cfg, options, features, router, license, ac, service, sql, teamService, userService, serviceAccountRetriever, actionSetService)
	if err != nil {
		return nil, err
	}
	return &DatasourcePermissionsService{srv}, nil
}
