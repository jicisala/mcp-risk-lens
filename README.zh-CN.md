# MCP Risk Lens

面向 MCP 配置文件的离线、确定性静态风险检查工具。

[English](README.md) · [专业评审服务](docs/professional-review.zh-CN.md)

MCP Risk Lens 用于在 AI Agent 启动工具服务器之前发现危险默认配置。它**不会**执行配置中的
命令、启动 MCP Server、上传文件或访问网络。

> 当前状态：早期公开 MVP。检测结果属于启发式静态分析，不能替代渗透测试、正式风险验收或
> 合规认证。

## 为什么需要它

一个 MCP 配置可能同时包含包执行、文件系统权限、远程地址和生产凭据。人工逐项检查耗时且
标准不一致。MCP Risk Lens 将常见检查固化为可重复执行的本地报告，也可以接入 CI。

## v0.1 检查项

| 规则 | 风险 |
|---|---|
| `MRL001` | 明文凭据及包含凭据的 URL |
| `MRL002` | Shell 解释器执行内联命令 |
| `MRL003` | `npx`、`uvx`、`bunx` 执行未锁定版本的软件包 |
| `MRL004` | 文件系统服务器拥有根目录或用户目录权限 |
| `MRL005` | 非本地远程端点使用明文 HTTP |
| `MRL006` | `admin`、`repo`、`*` 等过宽授权范围 |
| `MRL007` | 敏感能力缺少明确的人工审批策略 |
| `MRL008` | 单个服务器集中持有过多高价值凭据 |

## 快速开始

```bash
python -m pip install -e .
mcp-risk-lens scan examples/insecure.mcp.json
```

生成 HTML 报告：

```bash
mcp-risk-lens scan examples/insecure.mcp.json \
  --format html \
  --output reports/mcp-risk-report.html \
  --fail-on never
```

用于 CI 的 JSON 输出和风险阈值：

```bash
mcp-risk-lens scan .vscode/mcp.json --format json --output report.json --fail-on high
```

退出码：

- `0`：扫描完成，未达到失败阈值
- `1`：发现达到或超过 `--fail-on` 的问题
- `2`：输入或命令使用错误

## 安全特性

- 默认离线，无遥测，不需要 API Token。
- 只做静态分析，绝不执行配置中的命令。
- 报告中的疑似凭据统一替换为 `<redacted>`。
- 同一规则版本与配置产生相同顺序的检测结果。

请对敏感配置的副本进行扫描。除非报告仅包含合成数据，否则不要公开生成的报告。

## 开发

```bash
python -m pip install -e '.[dev]'
ruff check src tests
pytest -q
```

## 专业评审

开源扫描器只覆盖配置层。专业 MCP/AI Agent 治理评审还可以包含架构威胁建模、工具授权、人工
审批、审计与可观测性，以及按优先级排序的整改方案。详见[专业评审服务](docs/professional-review.zh-CN.md)。

请勿在 GitHub Issue 中提交凭据、私有配置、客户数据、内部代码或非公开架构。首次咨询只需要
提供可公开的概况。

## 许可证

Apache-2.0

