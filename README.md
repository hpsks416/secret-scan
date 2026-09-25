# secret-scan

只读安全审计：扫描本地工作区与 GitHub/Gitee 仓库里的泄露凭据、.env、私钥和敏感文件名，以 *** 脱敏报告，绝不回显真实密钥。

## 环境依赖

- 操作系统：Windows
- 运行时：Python 3（标准库）
- 第三方软件：无（仅依赖系统自带的 PowerShell / 标准库）

## 目录结构

    secret-scan/
    ├── SKILL.md    技能入口与工作流
    ├── evals.yaml
    ├── agents\openai.yaml
    ├── references\scan-guide.md
    ├── scripts\scan_secrets.py

## 安装

    # GitHub
    git clone https://github.com/hpsks416/secret-scan.git "$env:USERPROFILE\.dsh\skills\secret-scan"
    # 或 Gitee（国内直连）
    git clone https://gitee.com/hpsks416/secret-scan.git "$env:USERPROFILE\.dsh\skills\secret-scan"

克隆后 DSH 自动重新发现，无需构建。

## License

MIT License. See [LICENSE](LICENSE).
