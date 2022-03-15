import {
  Maybe,
  PageInfo,
  Repository,
  RepositoryVulnerabilityAlertEdge,
  RepositoryVulnerabilityAlert,
  SecurityAdvisoryEcosystem,
  SecurityAdvisorySeverity,
} from '@octokit/graphql-schema'

import { buildAlerts } from '../src/fetch-alerts';

const vulnerability = {pageInfo: {} as PageInfo, totalCount: 0};

const createSecVulnNode = (
  id: string,
  severity: SecurityAdvisorySeverity
): RepositoryVulnerabilityAlert => {
  return {
    id,
    createdAt: "now",
    repository: {
      name: "test-repo",
      owner: {
        login: "test-owner"
      }
    } as Repository,
    vulnerableManifestFilename: "vulnerableManifestFilename",
    vulnerableManifestPath: "vulnerableManifestPath",
    securityVulnerability: {
      severity,
      advisory: {
        severity,
        id: "advisory-id",
        cvss: {score: 1},
        cwes: vulnerability,
        description: "description",
        ghsaId: "ghsaId",
        origin: "origin",
        summary: "summary",
        publishedAt: "now",
        updatedAt: "now",
        vulnerabilities: vulnerability,
        identifiers: [],
        references: [],
      },
      package: {
        name: `${id}-${severity}`,
        ecosystem: "NPM" as SecurityAdvisoryEcosystem,
      },
      vulnerableVersionRange: ">=0.0.1",
      updatedAt: "now",
    }
  }
}

const testVulnerabilityAlerts: Maybe<Array<Maybe<RepositoryVulnerabilityAlertEdge>>> = [
  {node: createSecVulnNode("1", "CRITICAL"), cursor: ""},
  {node: createSecVulnNode("2", "HIGH"), cursor: ""},
  {node: createSecVulnNode("3", "MODERATE"), cursor: ""},
  {node: createSecVulnNode("4", "LOW"), cursor: ""},
];

test('buildAlerts - no alerts', () => {
  const targetSeverity = null;
  const actual = buildAlerts(targetSeverity, []);
  expect(actual.length).toEqual(0);
});

test('buildAlerts - no alerts filtered out when targetSeverity is null', () => {
  const targetSeverity = null;
  const actual = buildAlerts(targetSeverity, testVulnerabilityAlerts);
  expect(actual.length).toEqual(testVulnerabilityAlerts.length);

  const expected = ["1-CRITICAL", "2-HIGH", "3-MODERATE", "4-LOW"];
  expect(actual.map((alert) => alert.packageName)).toEqual(expected);
});

test('buildAlerts - alerts filtered out when targetSeverity is set', () => {
  const targetSeverity = "CRITICAL";
  const actual = buildAlerts(targetSeverity, testVulnerabilityAlerts);
  expect(actual.length).toEqual(1);

  const expected = ["1-CRITICAL"];
  expect(actual.map((alert) => alert.packageName)).toEqual(expected);
});

test('buildAlerts - all alerts filtered out when targetSeverity matches nothing', () => {
  const testVulnerabilityAlerts = [
    {node: createSecVulnNode("1", "CRITICAL"), cursor: ""},
    {node: createSecVulnNode("2", "LOW"), cursor: ""},
  ];
  const targetSeverity = "MODERATE";
  const actual = buildAlerts(targetSeverity, testVulnerabilityAlerts);
  expect(actual.length).toEqual(0);
});

test('buildAlerts - empty alerts filtered out', () => {
  const testVulnerabilityAlerts = [
    null,
    {node: createSecVulnNode("1", "CRITICAL"), cursor: ""},
    {node: createSecVulnNode("2", "LOW"), cursor: ""},
  ];
  const targetSeverity = null;
  const actual = buildAlerts(targetSeverity, testVulnerabilityAlerts);
  expect(actual.length).toEqual(2);

  const expected = ["1-CRITICAL", "2-LOW"];
  expect(actual.map((alert) => alert.packageName)).toEqual(expected);
});
