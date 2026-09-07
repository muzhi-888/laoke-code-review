# laoke-code-review · 代码审查助手

> 局内人·老K · 专注实体老板与开发者用 AI 落地实战

通用代码审查助手：覆盖**安全 / 正确 / 可维护 / 可读 / 性能 / 可测试**六维，内置纯标准库静态红线扫描器（硬编码密钥、SQL 拼接注入、裸 `except`、eval/exec、弱哈希、调试残留），输出分级审查报告（Markdown / JSON）。

## 包含内容

- `SKILL.md`：完整审查方法论与用法（六维框架、安全红线、性能反模式、可维护性规则、报告模板）
- `references/`：五份领域知识（六维清单、安全速查、性能反模式、可维护性规则、报告模板与分级）
- `scripts/review_scan.py`：零依赖静态扫描器（支持 Python AST 深度分析 + 多语言通用正则扫描）
- `hooks/guardrail.md`：合规护栏（硬拒恶意代码 / 规避安全检测 / 未授权入侵类请求）

## 快速开始

```bash
# 扫描整个目录（递归）
python scripts/review_scan.py ./src --format md

# 只看最严重的 N 条
python scripts/review_scan.py ./src --top 20

# 接 CI 流水线用 JSON
python scripts/review_scan.py ./src --format json > review.json
```

## 适用场景

- 提交前自查（先清 CRITICAL / HIGH 再提 PR）
- 审别人的 PR（按六维给分级意见）
- 接 CI 质量门禁（按 JSON 严重度决定是否 fail）
- 带新人做代码规范
- 接手遗留代码做体检

## 相关资源（同域推荐）

- 作者落地页（更多 AI 实战工具与模板合集）：https://muzhi-888.github.io/ju-nei-ren-lao-k/
- SkillHub 作者主页：在 SkillHub 搜索「局内人·老K」
- 更多 AI 落地实战知识库：见作者落地页导航

## License

MIT

## 免责声明

本工具仅供学习研究与合法合规的代码质量审查使用，不构成任何投资建议或收益承诺。使用者对最终交付代码的准确性、安全性与合规性负责。扫描器覆盖静态红线，逻辑正确性与业务匹配仍需人工 review。
