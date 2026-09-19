package guardian

import (
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/datasources"
)

var _ DatasourceGuardian = new(RBACGuardian)

// RBACGuardian resolves data source access from the permissions already loaded
// onto the identity. Permissions are scoped on UID while CanQuery is given an
// internal ID, which is why New takes the data sources the caller has resolved.
type RBACGuardian struct {
	user    identity.Requester
	uidByID map[int64]string
}

func newRBACGuardian(user identity.Requester, dataSources ...datasources.DataSource) *RBACGuardian {
	uidByID := make(map[int64]string, len(dataSources))
	for _, ds := range dataSources {
		uidByID[ds.ID] = ds.UID
	}
	return &RBACGuardian{user: user, uidByID: uidByID}
}

func (g *RBACGuardian) CanQuery(datasourceID int64) (bool, error) {
	uid, ok := g.uidByID[datasourceID]
	if !ok {
		return false, nil
	}
	check := accesscontrol.Checker(g.user, datasources.ActionQuery)
	return check(datasources.ScopeProvider.GetResourceScopeUID(uid)), nil
}

func (g *RBACGuardian) FilterDatasourcesByReadPermissions(ds []*datasources.DataSource) ([]*datasources.DataSource, error) {
	return g.filter(ds, datasources.ActionRead), nil
}

func (g *RBACGuardian) FilterDatasourcesByQueryPermissions(ds []*datasources.DataSource) ([]*datasources.DataSource, error) {
	return g.filter(ds, datasources.ActionQuery), nil
}

// A single Checker is reused across the whole list: it memoises the wildcard
// lookup from the scopes of its first call, which is only correct because every
// scope here shares the "datasources:uid:" prefix.
func (g *RBACGuardian) filter(ds []*datasources.DataSource, action string) []*datasources.DataSource {
	check := accesscontrol.Checker(g.user, action)
	filtered := make([]*datasources.DataSource, 0, len(ds))
	for _, d := range ds {
		if check(datasources.ScopeProvider.GetResourceScopeUID(d.UID)) {
			filtered = append(filtered, d)
		}
	}
	return filtered
}
