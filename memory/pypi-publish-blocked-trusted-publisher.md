---
name: pypi-publish-blocked-trusted-publisher
description: mcp-canary PyPI publish fails until a PyPI Trusted Publisher is configured
metadata:
  type: project
---

The `v0.1.0` tag-triggered `publish.yml` workflow fails at the publish step with
`invalid-publisher: no corresponding publisher`. PyPI Trusted Publishing (OIDC)
is **not yet configured** on PyPI for this project.

**Why:** The workflow uses `pypa/gh-action-pypi-publish` with OIDC; PyPI must have
a matching pending/trusted publisher before it will accept the token.

**How to apply:** To publish, the user must (only they can — it needs their PyPI
login): at https://pypi.org/manage/account/publishing/ add a pending publisher
with project `mcp-canary`, owner `aminrj`, repo `mcp-canary`, workflow
`publish.yml`, environment `pypi`. Then re-run the failed workflow (`gh run rerun
<id> --failed`) or re-push the `v0.1.0` tag. As of 2026-06-19 the package is not
on PyPI (404). The `v0.1.0` tag already points at the correct HEAD commit.
