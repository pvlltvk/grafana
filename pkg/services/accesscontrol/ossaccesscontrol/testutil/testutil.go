package testutil

import (
	testifymock "github.com/stretchr/testify/mock"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/infra/localcache"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	acdb "github.com/grafana/grafana/pkg/services/accesscontrol/database"
	"github.com/grafana/grafana/pkg/services/accesscontrol/ossaccesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/permreg"
	"github.com/grafana/grafana/pkg/services/accesscontrol/resourcepermissions"
	"github.com/grafana/grafana/pkg/services/apiserver"
	datasourceservice "github.com/grafana/grafana/pkg/services/datasources/service"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/folder/folderimpl"
	"github.com/grafana/grafana/pkg/services/licensing/licensingtest"
	"github.com/grafana/grafana/pkg/services/org/orgimpl"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	"github.com/grafana/grafana/pkg/services/search/sort"
	serviceaccountstest "github.com/grafana/grafana/pkg/services/serviceaccounts/tests"
	"github.com/grafana/grafana/pkg/services/sqlstore"
	"github.com/grafana/grafana/pkg/services/supportbundles/bundleregistry"
	"github.com/grafana/grafana/pkg/services/supportbundles/supportbundlestest"
	"github.com/grafana/grafana/pkg/services/team"
	"github.com/grafana/grafana/pkg/services/team/teamimpl"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/userimpl"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/legacysql"

	"github.com/grafana/grafana/pkg/storage/unified/resource"
	resourcepb "github.com/grafana/grafana/pkg/storage/unified/resourcepb"
)

func ProvideFolderPermissions(
	features featuremgmt.FeatureToggles,
	cfg *setting.Cfg,
	sqlStore *sqlstore.SQLStore,
) (*ossaccesscontrol.FolderPermissionsService, error) {
	actionSets := resourcepermissions.NewActionSetService()

	license := licensingtest.NewFakeLicensing()
	license.On("FeatureEnabled", "accesscontrol.enforcement").Return(true).Maybe()

	ac := acimpl.ProvideAccessControl(featuremgmt.WithFeatures())

	quotaService := quotatest.New(false, nil)

	acSvc := acimpl.ProvideOSSService(
		cfg, acdb.ProvideService(sqlStore), actionSets, localcache.ProvideService(),
		features, tracing.InitializeTracerForTest(), sqlStore, permreg.ProvidePermissionRegistry(),
		nil,
	)

	orgService, err := orgimpl.ProvideService(legacysql.NewDatabaseProvider(sqlStore), cfg, quotaService)
	if err != nil {
		return nil, err
	}
	teamSvc, err := teamimpl.ProvideService(legacysql.NewDatabaseProvider(sqlStore), cfg, tracing.InitializeTracerForTest(), nil)
	if err != nil {
		return nil, err
	}
	cache := localcache.ProvideService()

	userSvc, err := userimpl.ProvideService(
		legacysql.NewDatabaseProvider(sqlStore),
		orgService,
		cfg,
		teamSvc,
		cache,
		tracing.InitializeTracerForTest(),
		quotaService,
		bundleregistry.ProvideService(),
		nil,
	)
	if err != nil {
		return nil, err
	}

	searchMock := &resource.MockResourceClient{}
	searchMock.On("Search", testifymock.Anything, testifymock.Anything, testifymock.Anything).Return(&resourcepb.ResourceSearchResponse{TotalHits: 0}, nil).Maybe()
	searchMock.On("GetStats", testifymock.Anything, testifymock.Anything, testifymock.Anything).Return(&resourcepb.ResourceStatsResponse{}, nil).Maybe()
	fService := folderimpl.ProvideService(
		ac,
		userSvc, features, supportbundlestest.NewFakeBundleService(), nil, cfg, nil, tracing.InitializeTracerForTest(), searchMock, sort.ProvideService(), apiserver.WithoutRestConfig)

	return ossaccesscontrol.ProvideFolderPermissions(
		cfg,
		features,
		routing.NewRouteRegister(),
		sqlStore,
		ac,
		license,
		fService,
		acSvc,
		teamSvc,
		userSvc,
		&serviceaccountstest.FakeServiceAccountService{},
		actionSets,
		apiserver.ProvideDirectRestConfigProvider(),
	)
}

// DatasourcePermissionsEnv exposes the collaborators built alongside the data
// source permissions service. Team grants are only meaningful against real
// membership rows, so a test that wants to assert them needs the team and
// access control services too — asserting against a hand-supplied list of team
// IDs would only restate its own setup.
type DatasourcePermissionsEnv struct {
	Permissions   *ossaccesscontrol.DatasourcePermissionsService
	TeamService   team.Service
	UserService   user.Service
	AccessControl accesscontrol.Service
}

func ProvideDatasourcePermissions(
	features featuremgmt.FeatureToggles,
	cfg *setting.Cfg,
	sqlStore *sqlstore.SQLStore,
) (*ossaccesscontrol.DatasourcePermissionsService, error) {
	env, err := ProvideDatasourcePermissionsEnv(features, cfg, sqlStore)
	if err != nil {
		return nil, err
	}
	return env.Permissions, nil
}

func ProvideDatasourcePermissionsEnv(
	features featuremgmt.FeatureToggles,
	cfg *setting.Cfg,
	sqlStore *sqlstore.SQLStore,
) (*DatasourcePermissionsEnv, error) {
	actionSets := resourcepermissions.NewActionSetService()

	license := licensingtest.NewFakeLicensing()
	license.On("FeatureEnabled", "accesscontrol.enforcement").Return(true).Maybe()

	ac := acimpl.ProvideAccessControl(featuremgmt.WithFeatures())

	quotaService := quotatest.New(false, nil)

	acSvc := acimpl.ProvideOSSService(
		cfg, acdb.ProvideService(sqlStore), actionSets, localcache.ProvideService(),
		features, tracing.InitializeTracerForTest(), sqlStore, permreg.ProvidePermissionRegistry(),
		nil,
	)

	orgService, err := orgimpl.ProvideService(legacysql.NewDatabaseProvider(sqlStore), cfg, quotaService)
	if err != nil {
		return nil, err
	}
	teamSvc, err := teamimpl.ProvideService(legacysql.NewDatabaseProvider(sqlStore), cfg, tracing.InitializeTracerForTest(), nil)
	if err != nil {
		return nil, err
	}

	userSvc, err := userimpl.ProvideService(
		legacysql.NewDatabaseProvider(sqlStore),
		orgService,
		cfg,
		teamSvc,
		localcache.ProvideService(),
		tracing.InitializeTracerForTest(),
		quotaService,
		bundleregistry.ProvideService(),
		nil,
	)
	if err != nil {
		return nil, err
	}

	permissions, err := ossaccesscontrol.ProvideDatasourcePermissionsService(
		cfg,
		features,
		routing.NewRouteRegister(),
		sqlStore,
		ac,
		license,
		datasourceservice.ProvideDataSourceRetriever(sqlStore, features),
		acSvc,
		teamSvc,
		userSvc,
		&serviceaccountstest.FakeServiceAccountService{},
		actionSets,
	)
	if err != nil {
		return nil, err
	}

	return &DatasourcePermissionsEnv{
		Permissions:   permissions,
		TeamService:   teamSvc,
		UserService:   userSvc,
		AccessControl: acSvc,
	}, nil
}
