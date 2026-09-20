#!/usr/bin/env python3
"""Scan local and remote (GitHub + Gitee) repositories for leaked credentials.

Read-only. Reports findings with every matched secret redacted as "***".
Never prints or writes real token values. Never modifies any file or repo.

Environment:
  GITHUB_TOKEN    GitHub personal access token (optional; falls back to `gh auth token`)
  GITEE_TOKEN     Gitee personal access token (optional; needed for private repos)
  GH_USER         GitHub owner name (default hpsks416)
  GITEE_USER      Gitee owner name (default hpsks416)

Usage:
  python scan_secrets.py                       # scan remote GitHub + Gitee
  python scan_secrets.py --local <dir>         # scan a local directory tree
  python scan_secrets.py --skip-github         # Gitee only
  python scan_secrets.py --skip-gitee          # GitHub only
  python scan_secrets.py --max-file 200000     # skip blobs/files larger than N bytes
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

GH_USER = os.environ.get("GH_USER", "hpsks416").strip()
GITEE_USER = os.environ.get("GITEE_USER", "hpsks416").strip()

RISKY_FILE = re.compile(
    r"(^|/)(\.env(\.|$)|.*\.env$|.*\.pem$|.*\.key$|id_rsa|"
    r"credentials\.json|secret.*|.*secret.*|\.netrc$|\.npmrc$|\.pypirc$|.*\.p12$|.*\.pfx$)",
    re.IGNORECASE,
)


def gh_token() -> str:
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        return token
    candidates = ["gh"]
    env_bin = os.environ.get("GH_BIN", "").strip()
    if env_bin:
        candidates.append(env_bin)
    candidates.append(r"G:\KEY\2FA\GITHUBCLI\Application\gh.exe")
    for gh in candidates:
        try:
            out = subprocess.run([gh, "auth", "token"], capture_output=True, text=True, timeout=15)
            if out.returncode == 0 and out.stdout.strip():
                return out.stdout.strip()
        except Exception:
            continue
    return ""


def build_patterns() -> list[tuple[str, re.Pattern]]:
    patterns: list[tuple[str, re.Pattern]] = [
        ("github_token_ghp", re.compile(r"ghp_[A-Za-z0-9]{20,}")),
        ("github_token_gho", re.compile(r"gho_[A-Za-z0-9]{20,}")),
        ("github_token_pat", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
        ("openai_key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
        ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
        ("google_api_key", re.compile(r"AIza[0-9A-Za-z_-]{30,}")),
        ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        ("private_key_pem", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
        ("access_token_literal", re.compile(r"access_token\s*[=:]\s*[\"']?[A-Za-z0-9]{20,}[\"']?")),
        ("auth_basic_literal", re.compile(r"Authorization:\s*Basic\s+[A-Za-z0-9+/=]{20,}")),
    ]
    gitee_token = os.environ.get("GITEE_TOKEN", "").strip()
    if gitee_token and len(gitee_token) >= 8:
        patterns.append(("gitee_token_known", re.compile(re.escape(gitee_token))))
    token = gh_token()
    if token and len(token) >= 20:
        patterns.append(("github_token_current", re.compile(re.escape(token))))
    return patterns


def redact(text: str) -> str:
    for token in (os.environ.get("GITEE_TOKEN", "").strip(), gh_token()):
        if token:
            text = text.replace(token, "***")
    return text


def scan_text(text: str, patterns: list[tuple[str, re.Pattern]]) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    for name, rx in patterns:
        for m in rx.finditer(text):
            hits.append((name, "***"))
    return hits


def scan_file(path: str, text: str, patterns: list[tuple[str, re.Pattern]]) -> list[tuple[str, str]]:
    hits = scan_text(text, patterns)
    if RISKY_FILE.search(path) and not hits:
        hits.append(("risky_filename", "no plaintext secret matched"))
    return hits


def report(kind: str, location: str, sample: str) -> None:
    print("  ! %s: %s -> %s" % (kind, location, sample))


# ---------------------------------------------------------------------------
# Local scan
# ---------------------------------------------------------------------------

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__",
             ".idea", ".vscode", "dist", "build", ".cache"}


def scan_local(root: str, patterns: list[tuple[str, re.Pattern]], max_file: int) -> int:
    findings = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            full = os.path.join(dirpath, filename)
            rel = os.path.relpath(full, root).replace("\\", "/")
            try:
                if os.path.getsize(full) > max_file:
                    continue
                with open(full, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            hits = scan_file(rel, text, patterns)
            for kind, sample in hits:
                report(kind, rel, sample)
                findings += 1
    return findings


# ---------------------------------------------------------------------------
# Remote scan
# ---------------------------------------------------------------------------

def req(url: str, headers: dict[str, str] | None = None, timeout: int = 30):
    request = urllib.request.Request(url, headers=headers or {})
    return urllib.request.urlopen(request, timeout=timeout)


def gh_json(path: str, token: str):
    r = req("https://api.github.com" + path, {
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "User-Agent": "secret-scan",
    })
    return json.loads(r.read().decode("utf-8"))


def gitee_json(path: str, token: str):
    sep = "&" if "?" in path else "?"
    r = req("https://gitee.com/api/v5" + path + sep + "access_token=" + token)
    return json.loads(r.read().decode("utf-8"))


def gh_repos(token: str) -> list[dict]:
    out: list[dict] = []
    for page in range(1, 6):
        try:
            data = gh_json("/users/%s/repos?per_page=100&page=%d" % (GH_USER, page), token)
        except Exception:
            break
        if not data:
            break
        out += data
    return out


def gitee_repos(token: str) -> list[dict]:
    out: list[dict] = []
    for page in range(1, 6):
        try:
            data = gitee_json("/users/%s/repos?per_page=100&page=%d" % (GITEE_USER, page), token)
        except Exception:
            break
        if not data:
            break
        out += data
    return out


def scan_github(token: str, patterns: list[tuple[str, re.Pattern]], max_file: int) -> int:
    print("### GitHub repos (%s)" % GH_USER)
    findings = 0
    for repo in gh_repos(token):
        name = repo["name"]
        branch = repo.get("default_branch") or "main"
        qname = urllib.parse.quote(name, safe="")
        try:
            tree = gh_json("/repos/%s/%s/git/trees/%s?recursive=1" % (GH_USER, qname, urllib.parse.quote(branch, safe="")), token)
        except Exception as exc:
            print("  %s: tree error %s" % (name, exc))
            continue
        for item in tree.get("tree", []):
            if item.get("type") != "blob":
                continue
            path = item["path"]
            sha = item.get("sha")
            if not sha:
                continue
            try:
                blob = gh_json("/repos/%s/%s/git/blobs/%s" % (GH_USER, qname, sha), token)
            except Exception:
                continue
            if blob.get("size", 0) > max_file:
                continue
            content = blob.get("content", "")
            try:
                text = base64.b64decode(content).decode("utf-8", "replace")
            except Exception:
                text = ""
            hits = scan_file(path, text, patterns)
            for kind, sample in hits:
                report(kind, "%s/%s" % (name, path), sample)
                findings += 1
        print("  %s: ok" % name)
    return findings


def scan_gitee(token: str, patterns: list[tuple[str, re.Pattern]], max_file: int) -> int:
    print("### Gitee repos (%s)" % GITEE_USER)
    findings = 0
    for repo in gitee_repos(token):
        name = repo["name"]
        slug = repo.get("path") or repo.get("name")
        branch = repo.get("default_branch") or "master"
        qname = urllib.parse.quote(slug, safe="")
        try:
            tree = gitee_json("/repos/%s/%s/git/trees/%s?recursive=1" % (GITEE_USER, qname, urllib.parse.quote(branch, safe="")), token)
        except Exception as exc:
            print("  %s: tree error %s" % (name, exc))
            continue
        for item in tree.get("tree", []):
            if item.get("type") != "blob":
                continue
            path = item["path"]
            sha = item.get("sha")
            if not sha:
                continue
            try:
                blob = gitee_json("/repos/%s/%s/git/blobs/%s" % (GITEE_USER, qname, sha), token)
            except Exception:
                continue
            content = blob.get("content", "")
            try:
                text = base64.b64decode(content).decode("utf-8", "replace")
            except Exception:
                text = ""
            hits = scan_file(path, text, patterns)
            for kind, sample in hits:
                report(kind, "%s/%s" % (name, path), sample)
                findings += 1
        print("  %s: ok" % name)
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan for leaked credentials (read-only).")
    parser.add_argument("--local", help="scan a local directory tree instead of remote")
    parser.add_argument("--skip-github", action="store_true")
    parser.add_argument("--skip-gitee", action="store_true")
    parser.add_argument("--max-file", type=int, default=200000)
    args = parser.parse_args()

    patterns = build_patterns()
    total = 0

    if args.local:
        root = os.path.abspath(args.local)
        print("### Local scan: %s" % root)
        total = scan_local(root, patterns, args.max_file)
    else:
        token = gh_token()
        if not token:
            print("GITHUB_TOKEN not set and `gh auth token` failed; GitHub scan may fail.", file=sys.stderr)
        if not args.skip_github:
            try:
                total += scan_github(token, patterns, args.max_file)
            except Exception as exc:
                print("github scan error: %s" % exc, file=sys.stderr)
        gitee_token = os.environ.get("GITEE_TOKEN", "").strip()
        if not args.skip_gitee:
            if not gitee_token:
                print("GITEE_TOKEN not set; Gitee scan may be limited.", file=sys.stderr)
            try:
                total += scan_gitee(gitee_token, patterns, args.max_file)
            except Exception as exc:
                print("gitee scan error: %s" % exc, file=sys.stderr)

    print("DONE findings=%d" % total)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())