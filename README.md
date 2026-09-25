# secret-scan

Audit local and remote GitHub/Gitee repositories for leaked credentials, .env files, private keys, and other risky filenames, reporting redacted findings only. Use when the user asks to check, audit, or review token/secret security in their projects.

## 这是什么

DSH（DeepSeek Harness）skill —— 一个可由 AI agent 按需自动加载的能力单元。克隆到 skill 目录后，DSH 会依据上方描述自动发现并触发它，无需构建。

## 安装

最简单：用 [dsh-config](https://github.com/hpsks416/dsh-config) 的一键脚本 `install.ps1` 批量安装全部 skill。单个安装：

    # GitHub
    git clone https://github.com/hpsks416/secret-scan.git "$env:USERPROFILE\.dsh\skills\secret-scan"
    # 或 Gitee（国内直连更快）
    git clone https://gitee.com/hpsks416/secret-scan.git "$env:USERPROFILE\.dsh\skills\secret-scan"

克隆后 DSH 会自动重新发现，无需重启。更新用：

    git -C "$env:USERPROFILE\.dsh\skills\secret-scan" pull

## 目录结构

    secret-scan/
    ├── SKILL.md    技能入口与工作流
    ├── agents\openai.yaml
    ├── evals.yaml
    ├── references\scan-guide.md
    ├── scripts\scan_secrets.py

## 依赖

脚本以 Python 3 标准库为主，无第三方依赖（个别脚本如需额外依赖，见文件头注释）。

## License

MIT License. See [LICENSE](LICENSE).
