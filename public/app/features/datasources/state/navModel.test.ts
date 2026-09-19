import { PluginType, type DataSourceSettings } from '@grafana/data';
import { GrafanaEdition } from '@grafana/data/internal';
import config from 'app/core/config';

import { type GenericDataSourcePlugin } from '../types';

import { buildNavModel } from './navModel';

const permissionsTabId = 'datasource-permissions-uid';

function getDataSource(accessControl?: Record<string, boolean>) {
  return {
    id: 1,
    uid: 'uid',
    name: 'ClickHouse',
    type: 'grafana-clickhouse-datasource',
    accessControl,
  } as unknown as DataSourceSettings;
}

const plugin = {
  meta: {
    id: '1',
    type: PluginType.datasource,
    name: '',
    info: { logos: { large: '', small: '' } },
    includes: [],
  },
} as unknown as GenericDataSourcePlugin;

function permissionsTab(dataSource: DataSourceSettings) {
  return buildNavModel(dataSource, plugin).children?.find((child) => child.id === permissionsTabId);
}

describe('buildNavModel permissions tab', () => {
  const originalBuildInfo = config.buildInfo;
  const originalLicenseInfo = config.licenseInfo;

  beforeEach(() => {
    config.buildInfo = { ...originalBuildInfo, edition: GrafanaEdition.OpenSource };
    config.licenseInfo = { ...originalLicenseInfo, enabledFeatures: {} };
  });

  afterEach(() => {
    config.buildInfo = originalBuildInfo;
    config.licenseInfo = originalLicenseInfo;
  });

  it('shows the upgrade badge on an OSS build without enforcement', () => {
    const tab = permissionsTab(getDataSource());

    expect(tab).toBeDefined();
    expect(tab?.tabSuffix).toBeDefined();
  });

  it('drops the upgrade badge once enforcement is on', () => {
    config.licenseInfo.enabledFeatures = { 'dspermissions.enforcement': true };

    const tab = permissionsTab(getDataSource({ 'datasources.permissions:read': true }));

    expect(tab).toBeDefined();
    expect(tab?.tabSuffix).toBeUndefined();
  });

  it('hides the tab from users without permission once enforcement is on', () => {
    config.licenseInfo.enabledFeatures = { 'dspermissions.enforcement': true };

    expect(permissionsTab(getDataSource())).toBeUndefined();
  });
});
