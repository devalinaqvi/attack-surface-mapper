# GitHub Actions and local checks

## Does this require payment?

The workflow uses the standard `ubuntu-latest` GitHub-hosted runner. Standard runner compute is free for public repositories. GitHub Free includes 2,000 Actions minutes per month and 500 MB of artifact storage for private repositories; other repositories owned by the same account share the allowance. These terms were checked on 2026-09-21; consult [GitHub's current billing documentation](https://docs.github.com/en/billing/concepts/product-billing/github-actions).

This workflow does not use larger paid runners, upload artifacts, enable caches, deploy a site, or publish a package. It uses four Python-version jobs, so private-repository minutes accrue across the matrix. Jobs have a 15-minute timeout and superseded runs are canceled. Those settings limit individual runs, not your account's total spend; account budgets control paid usage.

## Account locked due to a billing issue

If the annotation says the job was not started because the account is locked due to a billing issue, GitHub prevented runner execution. That message does not establish a failing test, and changing Python code or deleting/recreating the repository does not resolve the underlying account restriction.

Check the repository owner's **Settings → Billing and licensing** for the actual account notice, quota, and budget status. If the lock is unexpected—especially for a public repository using standard runners—contact GitHub Support. The workflow cannot inspect or repair account billing. Do not assume that buying a paid plan is necessary based only on this message.

Once the account restriction is resolved, rerun the workflow. Until then, use the local commands in [usage](usage.md). You can disable the workflow from its Actions menu if you prefer local validation only.

## Workflow behavior

Pushes, pull requests, and manual dispatch run the suite for Python 3.10–3.13. `fail-fast: false` lets each supported version finish when another fails. Each job installs development dependencies, runs `make check`, and builds wheel/sdist packages. Repository token permissions are read-only, and checkout does not persist credentials.

Local validation on Python 3.10 is recorded separately from hosted CI. An account-blocked run does not validate the other Python versions. Read the first failing step in a job's logs to diagnose an actual installation, test, lint, type, or build error once jobs are allowed to run.
