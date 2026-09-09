# TaintP2X TypeScript 迁移清单

| 代码模块 | 需要迁移的内容 | 迁移方案 |
|---|---|---|
| `Source_Identification/analyze_assignments.py` | 迁移基于 Python `ast`、`.py` 文件、Python 类/函数/装饰器、对象属性和 LLM 客户端赋值关系实现的候选 LLM Source 识别，使其能够分析 TypeScript 项目；保持候选函数、参数及源码位置等下游所需信息的语义不变。 | 直接使用官方 TypeScript Compiler API，通过 Node.js/TypeScript 分析脚本遍历 TypeScript AST；按需使用 `Program` 和 `TypeChecker` 处理导入、别名和符号关系。分析脚本继续输出与原版一致的 `assignments` 和 `attribute_uses` JSON，供后续 Source 确认阶段消费；不引入 `ts-morph` 等第三方 AST 封装。 |
| `Source_Identification/confirm_source.py` | 将 Python 方法源码、模块路径、类名、方法名和参数相关处理迁移为 TypeScript 函数、方法、模块和参数语义；同步调整 LLM Source 确认 Prompt，并保持“确认函数是否返回 LLM 输出”的职责及结构化结果接口。 | 保持候选读取、源码提取、LLM 判断和结果保存流程不变；由官方 TypeScript Compiler API 提供函数/方法源码范围和标识信息，改写 TypeScript/Node.js LLM SDK 相关 Prompt，并继续输出 `is_llm_call`、`reason`、`method_name` 和 `full_method_path` 等下游字段。 |
| `Source_Identification/make_pysa_source.py` | 将已确认 LLM Source 转换为 `.pysa` 函数模型的逻辑迁移为 CodeQL 可消费的 Source 定义；处理 TypeScript 模块、类、函数、方法、调用和返回值的标识。 | 保持读取 `llm_analysis_<project>.json`、筛选 `is_llm_call=true` 及确认结果字段的流程不变；改为生成项目专用 CodeQL Source 谓词，匹配已确认的 TypeScript 函数调用，并由后续 CodeQL 数据流配置将调用返回节点初始化为 `LLMControlled` Source。保留类似 `isGPTDetectedSource` 的下游接口；不再生成 `.pysa` 函数签名，也不把 Python 参数列表作为核心模型输入。 |
| `Taint_Propagation/taint/*.pysa`、`taint.config` | 迁移 `.pysa` 中预定义的 LLM Source，以及命令与代码执行、文件系统、SQL、网络请求、HTTP 输出、日志、邮件和反序列化等 Sink；迁移 `taint.config` 中 Source、Sink、Transform 及其组合规则，使这些污点分析语义能够由 CodeQL 承载。 | 预定义 Source 首先覆盖 TypeScript/Node.js Agent 开发中常用的 LLM API；Sink 按现有 Python Sink 的安全语义迁移到 TypeScript/Node.js 中的对等 API。Source 和 Sink 均保持可扩展，首版不要求穷尽，后续允许继续补充；Source、Sink 类别及其组合关系保持现有 high-level 语义。目标项目依赖安装或必要的构建必须在分析前完成，作为迁移后环境准备的前提，不归 TaintP2X 核心逻辑负责。`generate_excel.py` 和 `llm_sources.xlsx` 仅作为辅助清单/转换工具，不属于主分析链，不要求迁移。 |
| `run_download_and_check.py::run_pysa_check` | 将 Pysa 配置生成、`pyre analyze` 执行、`taint-output.json` 检查和结果保存这一后端边界迁移为 CodeQL 分析执行、机器可读结果输出及结果检查。 | 保留该函数作为静态分析后端 Driver，保持调用时机、`has_issue` 返回值、超时、错误处理和结果目录逻辑不变；改为驱动 CodeQL database analyze/query，读取 SARIF/BQRS，并在此边界转换为后续 LLM 验证器使用的统一 issue/path 结构。目标依赖安装、必要构建和 CodeQL database 准备由环境准备阶段负责，该 Driver 只消费已准备好的源码和 CodeQL database。 |
| `LLM-assisted_Validation/ds_llm_source_determine_mul.py` | 将 Pysa `taint-output.json` 的 issue/source trace 解析迁移到 CodeQL 结果适配接口；将 `.py`、`def`、缩进函数边界和 Python LLM API Prompt 迁移为 TypeScript 文件、函数/方法边界及 LLM API 语义。 | 保持统一 issue/path 输入、Source 判断、LLM 调用、日志目录和结果字段不变；使用官方 TypeScript Compiler API 提取函数、方法、箭头函数或模块级代码，并将 Python LLM API 判断 Prompt 改为 TypeScript/Node.js 语义。不直接解析 CodeQL 原始 SARIF/BQRS。 |
| `LLM-assisted_Validation/ds_llm_fully_determine_mul.py` | 将 Pysa issue、callable 和 trace chain 的消费迁移到 CodeQL 路径结果；将 Python 函数查找、源码提取、Sink 示例及污点传播 Prompt 迁移为 TypeScript/Node.js 语义，保持逐路径 LLM 验证和综合判断接口。 | 保持逐函数分析、重复函数去重、sanitizer 补充、漏洞类型提示、整链综合判断及结果字段不变；读取统一的 CodeQL Source-to-Sink 路径结果，使用官方 TypeScript Compiler API 提取 `.ts`/`.tsx`/必要的 `.js` 函数或方法源码，并将 Python/原生 API 示例改为 TypeScript/Node.js 语义。 |

## 测试目标

| 项目 | 内容 |
|---|---|
| 仓库 | `FlowiseAI/Flowise` |
| 链接 | <https://github.com/FlowiseAI/Flowise> |
| 主要语言 | TypeScript |
| 规模参考 | GitHub 仓库大小约 83 MB，约 55k stars |
| 测试版本 | `flowise@2.2.6` |
| 固定提交 | `da04289ecf1c25dc4894737e9d00eac9f6d9ec7d` |
| 漏洞 | `CVE-2025-55346`，`CWE-94`，CVSS `9.8` |
| 漏洞描述 | 用户可控输入流入不安全的动态 `Function` 构造器，导致网络攻击者执行任意 JavaScript 代码。 |
| 选择理由 | 仓库规模适中，版本和提交可固定，漏洞是清晰的用户输入到动态代码执行 Sink 的 TypeScript 数据流，适合验证迁移后的 Source、Sink 和 CodeQL 路径分析。 |

### 迁移测试模型

| 配置项 | 内容 |
|---|---|
| 模型 | `deepseek-v4-flash` |
| Base URL | `https://api.deepseek.com` |
| Thinking | `{"thinking":{"type":"disabled"}}` |
| API Key | `sk-281d0267e93b4955acf0847a0ebd73c0` |
