package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ac "github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/org"
)

func roleByName(t *testing.T, regs []ac.RoleRegistration, name string) ac.RoleRegistration {
	t.Helper()

	for _, reg := range regs {
		if reg.Role.Name == name {
			return reg
		}
	}
	t.Fatalf("role %q was not registered", name)
	return ac.RoleRegistration{}
}

func TestFixedRoleRegistrationsDatasourceGrants(t *testing.T) {
	t.Run("without enforcement the reader role is granted to Viewer", func(t *testing.T) {
		reader := roleByName(t, FixedRoleRegistrations(false, false), datasourcesReaderRoleName)

		assert.Equal(t, []string{string(org.RoleViewer)}, reader.Grants)
	})

	t.Run("with enforcement the reader role is granted to Admin only", func(t *testing.T) {
		reader := roleByName(t, FixedRoleRegistrations(false, true), datasourcesReaderRoleName)

		assert.Equal(t, []string{string(org.RoleAdmin)}, reader.Grants)
	})

	t.Run("the reader role always carries read and query on all data sources", func(t *testing.T) {
		for _, enforced := range []bool{false, true} {
			reader := roleByName(t, FixedRoleRegistrations(false, enforced), datasourcesReaderRoleName)

			require.Len(t, reader.Role.Permissions, 2)
			assert.Equal(t, datasources.ActionRead, reader.Role.Permissions[0].Action)
			assert.Equal(t, datasources.ScopeAll, reader.Role.Permissions[0].Scope)
			assert.Equal(t, datasources.ActionQuery, reader.Role.Permissions[1].Action)
			assert.Equal(t, datasources.ScopeAll, reader.Role.Permissions[1].Scope)
		}
	})

	t.Run("Org Admins keep read and query through the writer role either way", func(t *testing.T) {
		for _, enforced := range []bool{false, true} {
			writer := roleByName(t, FixedRoleRegistrations(false, enforced), "fixed:datasources:writer")

			assert.Equal(t, []string{string(org.RoleAdmin)}, writer.Grants)
			assert.Contains(t, writer.Role.Permissions, ac.Permission{
				Action: datasources.ActionQuery, Scope: datasources.ScopeAll,
			})
		}
	})

	t.Run("the built in data source reader is granted to Viewer regardless", func(t *testing.T) {
		for _, enforced := range []bool{false, true} {
			builtin := roleByName(t, FixedRoleRegistrations(false, enforced), "fixed:datasources.builtin:reader")

			assert.Equal(t, []string{string(org.RoleViewer)}, builtin.Grants)
		}
	})
}
