![marketing](https://user-images.githubusercontent.com/2741371/146811728-d2d9302b-f7f9-4296-82e3-e9812e562af9.png)

## @openmindlearning/action-cve

A fork of @kunalnagarco's [Github action] that sends Dependabot Vulnerability Alerts to multiple sources:

- Microsoft Teams
- Slack
- PagerDuty
- Zenduty

## Usage

```
name: 'Check for Vulnerabilities'

on:
  schedule:
    - cron: '0 */6 * * *' # every 6 hours

jobs:
  main:
    runs-on: ubuntu-latest
    steps:
      # X.X.X - Latest version available at: https://github.com/openmindlearning/action-cve/releases
      - uses: openmindlearning/action-cve@vX.X.X
        with:
          token: ${{ secrets.PERSONAL_ACCESS_TOKEN }}
          count: 10
          target_severity: CRITICAL,HIGH
          slack_webhook: ${{ secrets.SLACK_WEBHOOK }}
          pager_duty_integration_key: ${{ secrets.PAGER_DUTY_INTEGRATION_KEY }}
          zenduty_api_key: ${{ secrets.ZENDUTY_API_KEY }}
          zenduty_service_id: ${{ secrets.ZENDUTY_SERVICE_ID }}
          zenduty_escalation_policy_id: ${{ secrets.ZENDUTY_ESCALATION_POLICY_ID }}
```

## Action Inputs

| Input                          | Description                                                                                        |
|--------------------------------|----------------------------------------------------------------------------------------------------|
| `token`                        | [Required] Github Personal Access Token. Create one [here](https://github.com/settings/tokens)     |
| `count`                        | Limit of alerts pulled from Github. Defaults to 20                                                 |
| `target_severity`              | Comma separated list to filter alerts by severity (accepts: "CRITICAL", "HIGH", "MODERATE", "LOW") |
| `slack_webhook`                | [Slack Incoming Webhook URL]                                                                       |
| `pager_duty_integration_key`   | Pager Duty [Service Integration Key]. Also known as Routing key.                                   |
| `zenduty_api_key`              | Create a Zenduty API Key by visiting Account Settings > API Keys                                   |
| `zenduty_service_id`           | Zenduty Service ID:  https://docs.zenduty.com/docs/services                                        |
| `zenduty_escalation_policy_id` | Zenduty Escalation Policy ID:  https://docs.zenduty.com/docs/escalationpolicies                    |


### Github Token Requirements

In order for your token to be able to access the information,
you must allow it the following privileges:

```
user
public_repo
repo
repo_deployment
repo:status
read:repo_hook
read:org
read:public_key
read:gpg_key
```

For more information, please check the [Github GraphQL docs]


## Attributions

- Bug icon: Made by Freepik from [https://www.flaticon.com/](https://www.flaticon.com/)



[Github action]: https://github.com/features/actions
[Github GraphQL docs]: https://docs.github.com/en/graphql/guides/forming-calls-with-graphql#authenticating-with-graphql
[Slack Incoming Webhook URL]: https://api.slack.com/messaging/webhooks
[Service Integration Key]: https://support.pagerduty.com/docs/services-and-integrations#section-events-api-v2
