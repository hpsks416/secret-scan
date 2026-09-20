# Secret Scan — Finding Guide

## Finding taxonomy

- `github_token_ghp` / `github_token_gho` / `github_token_pat`: classic, OAuth, or fine-grained GitHub PATs.
- `github_token_current` / `gitee_token_known`: the token supplied to the scanner itself. A hit means the token was committed somewhere; rotate it immediately.
- `openai_key`, `slack_token`, `google_api_key`, `aws_access_key_id`: common third-party credential shapes.
- `private_key_pem`: a PEM private key block.
- `access_token_literal`: an `access_token=`/`access_token:` assignment with a long value.
- `auth_basic_literal`: a hardcoded `Authorization: Basic ...` header.
- `risky_filename`: a sensitive filename (`.env`, `.key`, `id_rsa`, ...) with no plaintext credential pattern matched. Inspect it manually.

## False positives to expect

- A `.env` that only sets `PYTHONPATH` (or similar non-secret vars) is not a leak; report it as benign after inspection.
- `github_pat_`-like strings inside documentation/examples may be placeholders; confirm they are not real tokens.
- `AKIA...`-shaped strings in docs can be example IDs; check they do not pair with a secret key.

## Remediation

1. Rotate any real credential found.
2. Remove the file from the repo (`git rm --cached <path>` then commit) and add it to `.gitignore`.
3. For history leaks, rewrite history (e.g. `git filter-repo`) — only with explicit user approval, and coordinate with anyone who cloned the repo.
4. Prefer environment variables or a secret manager going forward; never commit `.env`, tokens, or key files.