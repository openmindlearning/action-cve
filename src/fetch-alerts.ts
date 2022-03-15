import { Alert, toAlert } from './entities'
import {
  Maybe,
  Repository,
  RepositoryVulnerabilityAlertEdge,
  SecurityAdvisorySeverity,
} from '@octokit/graphql-schema'
import { getOctokit } from '@actions/github'

export const fetchAlerts = async (
  gitHubPersonalAccessToken: string,
  repositoryName: string,
  repositoryOwner: string,
  count: number,
  targetSeverity: Array<SecurityAdvisorySeverity>,
): Promise<Alert[] | []> => {
  const octokit = getOctokit(gitHubPersonalAccessToken)
  const { repository } = await octokit.graphql<{
    repository: Repository
  }>(`
    query {
      repository(owner:"${repositoryOwner}" name:"${repositoryName}") {
        vulnerabilityAlerts(last: ${count}) {
          edges {
            node {
              id
              repository {
                name
                owner {
                  login
                }
              }
              securityAdvisory {
                id
                description
                cvss {
                  score
                  vectorString
                }
                permalink
                severity
                summary
              }
              securityVulnerability {
                firstPatchedVersion {
                  identifier
                }
                package {
                  ecosystem
                  name
                }
                vulnerableVersionRange
                advisory {
                  cvss {
                    score
                    vectorString
                  }
                  summary
                }
              }
            }
          }
        }
      }
    }
  `);
  return buildAlerts(targetSeverity, repository.vulnerabilityAlerts?.edges);
}


export const buildAlerts = (
  targetSeverity: Array<SecurityAdvisorySeverity>,
  githubAlerts?: Maybe<Array<Maybe<RepositoryVulnerabilityAlertEdge>>>,
): Array<Alert> => {
  /*
  * Returns a list of Alerts that match the target severity.
  * If no severity is supplied, then this will filter out no alerts.
  */

  if (!githubAlerts) {
    return [];
  }

  const alerts: Array<Alert> = [];
  for (const alert of githubAlerts) {
    if (alert && alert.node) {
      const alertSeverity = alert.node.securityVulnerability?.severity;
      if (targetSeverity.length === 0 || (alertSeverity && targetSeverity.includes(alertSeverity))) {
        alerts.push(toAlert(alert.node));
      }
    }
  }
  return alerts;
}
