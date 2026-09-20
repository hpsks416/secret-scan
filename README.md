# secret-scan

Codex 专用安全审计 SKILL：只读扫描本地工作区与 GitHub/Gitee 云端仓库，发现泄露的 token、`.env`、私钥及敏感文件名，并以 `***` 脱敏后报告。绝不回显真实凭据，绝不修改任何文件或仓库。

## 安装

已安装到本机技能目录：

```text
C:\Users\Razer\.codex\skills\secret-scan
```

目录结构：

```text
secret-scan/
|-- SKILL.md                 技能入口与工作流
|-- agents/openai.yaml       UI 元数据
|-- scripts/scan_secrets.py  本地 + GitHub + Gitee 扫描器
`-- references/scan-guide.md 命中类型、误报与修复指南
```

## 使用

```powershell
$env:PYTHONUTF8='1'

# 扫描 GitHub + Gitee 云端仓库（owner: hpsks416）
python scripts/scan_secrets.py

# 扫描本地 Codex 工作区
python scripts/scan_secrets.py --local "C:\Users\Razer\Documents\Codex"

# 仅 GitHub / 仅 Gitee
python scripts/scan_secrets.py --skip-gitee
python scripts/scan_secrets.py --skip-github
```

凭据通过环境变量注入，不写入仓库：

- `GITHUB_TOKEN`（缺省时回退到 `gh auth token`）
- `GITEE_TOKEN`

## 默认扫描对象

- 远端：GitHub 与 Gitee 上 `hpsks416` 的全部仓库。
- 本地：`C:\Users\Razer\Documents\Codex`（可用 `--local` 覆盖）。

## 检测内容

GitHub token（`ghp_`/`gho_`/`github_pat_`）、当前生效的 GitHub/Gitee token、OpenAI/Slack/Google/AWS 密钥特征、PEM 私钥、`access_token=...`、`Authorization: Basic ...`，以及 `.env`、`*.key`、`id_rsa`、`credentials.json`、`.netrc`、`.npmrc`、`.pypirc`、`*.p12`、`*.pfx` 等敏感文件名。

## License

MIT