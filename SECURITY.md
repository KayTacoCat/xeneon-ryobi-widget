# Security policy

Security fixes target the current `main` branch. Update deployed copies to the
latest revision after reviewing and merging fixes.

## Report a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/KayTacoCat/xeneon-ryobi-widget/security/advisories/new)
to report suspected vulnerabilities, including steps to reproduce, affected
versions, and the expected impact. Keep credentials, private information, and
exploit details out of public issues and pull requests.

## Security scope

This repository is a static public widget. Its source, feed identifier, and
browser requests are visible to anyone who loads it. Do not add private feeds,
credentials, or personal data to the page or Git history.

The widget loads a public Reddit feed and an embedded wall from RSS.app. Feed
content and the embedded provider remain external trust boundaries. This
repository does not control RSS.app, Reddit, their content, or their service
availability.

Automated checks cover widget regression tests and CodeQL analysis of JavaScript
and GitHub Actions. Actions are pinned to full commit hashes and checked for
updates weekly by Dependabot. Review each update before merging it.
