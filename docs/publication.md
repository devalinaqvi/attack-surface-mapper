# Public repository and report privacy

## What can be published

The repository contains analyzer source, documentation, tests, and a synthetic demo. Real application lockfiles, manifests, vendor trees, and reports should remain outside it. The analyzer retains package metadata verbatim, so its JSON output is not automatically safe to publish: source/dist URLs may contain credentials, scripts can contain sensitive arguments, and names/references can expose private projects.

`reports/`, `scan-results/`, root `report*.json`/`report*.txt`, environment files, common private-key containers, local IDE settings, logs, and build directories are ignored. Ignore rules are only a guard against accidental staging. They do not stop `git add -f`, remove already tracked files, or erase history. Avoid putting real credentials in example files.

## Review before publishing

```sh
git status --short
git diff --cached --stat
git diff --cached --check
git diff --cached
git log --all --format=fuller
```

Review the tracked files and every reachable commit, not just the working tree. Look for credentials, private URLs, personal paths, real customer/project fixtures, and unintentionally published contact information. Inspect wheel/sdist contents too. Pattern scanning helps, but no automated scan guarantees the absence of secrets.

Git author and committer email addresses are public commit metadata. If you want email privacy, copy your exact GitHub noreply address from **Settings → Emails** and configure it before committing. Do not guess a GitHub numeric ID or change someone else's identity. Existing commits retain their original metadata unless explicitly rewritten.

Codex-assisted commits use this trailer, verified against the installed Codex application:

```text
Co-authored-by: Codex <noreply@openai.com>
```

A prose mention is not a Git co-author trailer. The trailer records assistance; GitHub contributor display depends on its account/email association and repository rules. It does not guarantee a named contributor account or imply endorsement.

If sensitive credentials were already published, revoke/rotate them and address the published history. Merely deleting a local file or rewriting a commit does not invalidate an exposed credential or erase copies held elsewhere. No publishing or history force-push is performed by the build or CI workflow.
