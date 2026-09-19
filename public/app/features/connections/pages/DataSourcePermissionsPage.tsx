import { useParams } from 'react-router-dom-v5-compat';

import { Permissions } from 'app/core/components/AccessControl/Permissions';
import { Page } from 'app/core/components/Page/Page';
import { contextSrv } from 'app/core/services/context_srv';
import { EditDataSourceActions } from 'app/features/datasources/components/EditDataSourceActions';
import { useDataSourceInfo } from 'app/features/datasources/components/useDataSourceInfo';
import { useDataSource, useInitDataSourceSettings } from 'app/features/datasources/state/hooks';
import { AccessControlAction } from 'app/types/accessControl';

import { useDataSourceTabNav } from '../hooks/useDataSourceTabNav';

export function DataSourcePermissionsPage() {
  const { uid = '' } = useParams<{ uid: string }>();
  useInitDataSourceSettings(uid);

  const dataSource = useDataSource(uid);
  const { navId, pageNav, dataSourceHeader } = useDataSourceTabNav('permissions');

  const info = useDataSourceInfo({
    dataSourcePluginName: pageNav.dataSourcePluginName,
    alertingSupported: dataSourceHeader.alertingSupported,
    alertingLoading: dataSourceHeader.alertingLoading,
  });

  const canSetPermissions = contextSrv.hasPermissionInMetadata(
    AccessControlAction.DataSourcesPermissionsWrite,
    dataSource
  );

  return (
    <Page navId={navId} pageNav={pageNav} info={info} actions={<EditDataSourceActions uid={uid} />}>
      <Page.Contents>
        <Permissions resource="datasources" resourceId={uid} canSetPermissions={canSetPermissions} />
      </Page.Contents>
    </Page>
  );
}
