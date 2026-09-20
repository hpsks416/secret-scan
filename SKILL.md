---
name: secret-scan
description: Audit local and remote GitHub/Gitee repositories for leaked credentials, .env files, private keys, and other risky filenames, reporting redacted findings only. Use when the user asks to check, audit, or review token/secret security in their projects.
---

# Secret Scan

Read-only security audit for credentials accidentally committed to local projects or pushed to GitHub/Gitee. Reports findings with every matched value redacted as `***`; it never prints, logs, or writes real token values and never modifies any file or remote repo.

## When to use

- "检查 token / 密钥 / .env 是否泄露"
- "审计云端仓库安全性"
- "检查我的 GitHub/Gitee 项目有没有提交凭据"

Do not use this skill for general code review, dependency scanning, or unrelated cleanup. It only finds credential-shaped content.

## Default targets

- Remote: every repo under GitHub and Gitee owner `hpsks416` (public and private).
- Local: the Codex workspace `C:\Users\Razer\Documents\Codex` (override with `--local <dir>`).

A general "检查 token/密钥安全" request should cover both the remote repos and this local workspace. A request about a specific project may limit the scan to that repo or directory only.

## Workflow

1. Run the bundled scanner with `PYTHONUTF8=1` (Windows) so non-ASCII repo names work.
2. Remote scan (default): `python "<skill-dir>\scripts\scan_secrets.py"`.
3. Local workspace scan: `python "<skill-dir>\scripts\scan_secrets.py" --local "C:\Users\Razer\Documents\Codex"`.
4. Gitee-only / GitHub-only: add `--skip-github` or `--skip-gitee`.
5. Review each `!` finding. A `risky_filename` hit means the file matches a risky name but contains no plaintext credential pattern; inspect it manually and redact any real value before reporting.
6. Summarize findings as a table: platform, repo/path, finding type, and (redacted) sample. State clearly when a finding is a false positive (for example a `.env` holding only a `PYTHONPATH` line).

## Credentials and network

- GitHub token: read `GITHUB_TOKEN`, else fall back to `gh auth token`. Never store it in the skill, repo config, or output.
- Gitee token: read `GITEE_TOKEN`. Do not hardcode it in any script or commit.
- On this machine a stale proxy (127.0.0.1:9) can break API calls; if requests fail with proxy errors, clear `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` (and the Git proxy equivalents) and set `NO_PROXY=*` before retrying.
- Gitee repo names must be URL-encoded when calling the API; the bundled script already handles non-ASCII repo names by using the repo `path` slug (for example `helios`, `416`).

## What it detects

- GitHub tokens (`ghp_`, `gho_`, `github_pat_`), the currently active GitHub/Gitee tokens, OpenAI/Slack/Google/AWS key patterns, PEM private keys, `access_token=...`, and `Authorization: Basic ...`.
- Risky filenames: `.env`, `*.env`, `*.pem`, `*.key`, `id_rsa`, `credentials.json`, `.netrc`, `.npmrc`, `.pypirc`, `*.p12`, `*.pfx`, and names containing `secret`.

## Safety

- Read-only: never edit, delete, rotate, or revoke anything unless the user separately asks.
- Redact every matched value as `***` in the final answer; do not echo tokens back to the user or into logs.
- If a real credential is found, recommend immediate rotation and, if asked, removal via git history rewrite; do not do destructive rewrites unprompted.

## License Default

When packaging this skill as a repository, use the MIT license with the current year and owner `hpsks416`.

## References

- `scripts/scan_secrets.py`: the bundled local + GitHub + Gitee scanner.
- `references/scan-guide.md`: finding taxonomy, false-positive guidance, and remediation notes.