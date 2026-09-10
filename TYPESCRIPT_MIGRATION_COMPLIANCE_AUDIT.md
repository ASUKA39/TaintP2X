# TypeScript 迁移合规审计

本文档记录 `main`（原版 Python TaintP2X）与 `typescript-port`（TypeScript 迁移分支）的行为差异。审计标准是：迁移只替换语言相关实现和 Pysa 后端接口，保持原版的 high-level 流程、职责、输入输出、规则语义和结果契约；不得新增研究分类、额外筛选逻辑或新的分析阶段。

## 迁移任务总原则与测试用例定位

本次任务的目标是把 TaintP2X 从 Python 迁移到 TypeScript，并将 Pysa 替换为 CodeQL，同时交付一个在功能、流程和语义上仍然属于原版 TaintP2X 的 TypeScript 版本，而不是借用原项目名称重新实现一个相似工具。

迁移必须遵循以下原则：

- 保持原版的 high-level 流程、阶段顺序、职责边界、输入输出、规则语义和 artifact 契约；不新增、不删除原版功能。
- 基于原版代码进行替换式修改。TypeScript 语言实现和 CodeQL 后端适配应收敛到原版对应模块中，不另起一套平行分析流程。
- 允许以 TypeScript Compiler API/`TypeChecker` 替换 Python AST，以 CodeQL driver 替换 Pysa driver，但替换只发生在语言和后端接口边界。
- Source Identification 的高层逻辑保持为“精确定位 LLM 对象/API -> 精确追踪其使用位置 -> 定位所在函数 -> 由 LLM 确认函数是否调用 LLM 并返回模型输出”。对象识别和使用追踪可以按 TypeScript 语言特性适配，但不得用裸方法名、变量名或文本关键词进行宽泛猜测。
- Source、Sink、Sanitizer、Transform 及规则必须按安全语义进行对等迁移，精确限定包、符号、调用对象、参数位置和传播方向；不能用字符串名单或测试用例特征粗暴近似。
- `FileOperation` 等论文中的关键设计必须保留完整语义。若找不到可靠的 TypeScript/CodeQL 对等表达，宁可明确记录该具体能力不迁移，也不能用近似规则伪造覆盖。
- 保留原版前后两次 Source 确认、`FullyDeterminer` 的逐函数与整链分析、阶段门控、中间文件、去重、结果复用和断点恢复。
- 原版已有的实现缺口不在迁移中擅自补全；例如 `vulnerability_types` 在原版只有消费逻辑而没有明确生产链，就保留这一实际状态并记录，不自行设计新的生产逻辑。
- 原版中文 Prompt 可以严格对等翻译成英文，但分析问题、证据要求、阶段职责和返回字段不能改变。
- 远程 LLM 的通信层可以根据实际协议适配模型名、端点和非内容参数，但模型和通信配置必须来自运行配置，不能硬编码；适配层不得改写实际发送的 Prompt 和上下文。
- 配置只描述目标、运行环境和后端位置，不能成为新增筛选、分类或实验逻辑的控制面。

当前选定的测试用例是 Flowise `flowise@2.2.6`（CVE-2025-55346）。它是迁移开发期间的真实端到端运行样例，用于确认 Docker 环境、目标依赖、Source 识别、CodeQL 建库与分析、原版 LLM 验证流程以及结果回收能够按预期工作。该条目是基于“理论上可能被工具检测”的条件选取的样例，不是工具能力边界的定义，也不是必须检出的测试基准。实际漏洞可能超出迁移后工具的检测能力；即使最终没有检出，也不单独否定迁移。测试用例不得反向驱动实现，不得据此硬编码函数名、路径、Sink、CWE、规则或扩大 Source/Sink 覆盖。迁移完成的判断应以流程能够在真实项目上按预期运行，且实现与原版功能和语义契约保持一致为准。

审计基线：

- 原版：`main` 分支。
- 当前迁移实现：`typescript-port` 分支；文中“当前”指迁移分支已经提交的实现，另注明当前工作树中已经改动但尚未提交的修正。
- 原版主要链路：Source Identification -> Source 确认 -> Pysa Source 模型生成 -> Pysa 污点分析 -> Source/Full LLM 验证 -> issue 结果与分析日志。

## 一、允许的迁移范围

下列变化是迁移 TypeScript 所必需的，不属于功能扩展：

| 原版 | 当前迁移实现 | 原因 |
|---|---|---|
| Python `ast` 遍历 `.py` 文件 | TypeScript Compiler API 遍历 `.ts`/`.tsx`（并兼容 JavaScript 文件） | TypeScript 没有 Python AST，必须使用对应语言的语法树和源码范围 API。 |
| Pysa `.pysa` Source/Sink 模型 | CodeQL JavaScript/TypeScript 数据流模型和查询 | 目标后端从 Pysa 替换为 CodeQL。 |
| Pyre/Pysa driver | CodeQL database create/analyze driver | 保持静态分析后端边界，但替换底层工具。 |
| Python 项目镜像 | Node/TypeScript 项目镜像 | 提供 TypeScript Compiler API 和目标语言运行环境。 |
| Python 方法源码提取 | TypeScript 函数/方法/箭头函数源码范围提取 | 保持后续 Source 确认所需的源码输入。 |

这些变化只有在保持原版语义和接口的前提下才合规。

## 二、明确的功能扩展

### 1. 新增漏洞分类体系

| 项目 | 原版 | 当前迁移实现 | 前因 | 后果 |
|---|---|---|---|---|
| 漏洞分类 | 原版没有 `LLM-in-the-Loop`、`traditional`、`Not-Sure`。原版判断 `is_vulnerability`，并按 Sink 保存 `vulnerability_types`。 | TypeScript 后验证器曾要求模型返回上述三个新分类，并在报告中统计三类数量。当前工作树已删除这套分类要求，但修正尚未提交；历史提交和已生成报告仍含有旧分类。 | 将本研究的漏洞分类标准误当成 TaintP2X 迁移需求。 | 改变实验对象和输出含义，使迁移结果不能与原版结果直接比较。 |

处理结论：已清理。迁移代码不生成或统计 `LLM-in-the-Loop`、`traditional`、`Not-Sure`，继续使用原版 `is_vulnerability` 和可选 `vulnerability_types` 语义。历史 `.workspace` 报告不属于当前运行输出，最终复现时应清理。

### 2. 新增独立 CodeQL 后验证阶段

| 项目 | 原版 | 当前迁移实现 | 前因 | 后果 |
|---|---|---|---|---|
| 后验证入口 | `SourceDeterminer.process_project` 读取 Pysa issue，保存 issue 资料和 Source 信息；随后 `FullyDeterminer.process_project` 处理已筛选 issue。 | 新增 `scripts/validate_codeql_results.py`，直接读取 SARIF，逐条调用 Source 和 Fully 判断。 | 为了快速消费 CodeQL SARIF，另写了一个独立适配器。 | 流程从“适配原有验证器”变成“新增一条验证流水线”；原版筛选、目录、断点和合并逻辑没有完整保留。 |

处理结论：已完成。`SourceDeterminer.process_project` -> `FullyDeterminer.process_project` 仍是唯一后验证入口；CodeQL/SARIF 只在 `run_download_and_check.py` 的后端边界转换为原版 issue/path 结构，独立 validator 已删除。

### 3. 新增非原版 CLI 行为

`scripts/validate_codeql_results.py` 增加了 `--contains`、`--limit`、`--workers`、`--language`。这些选项不是 TypeScript 语义迁移所需，也不是原版验证器的接口。它们改变任务选择、并发方式和执行范围，属于额外功能，应从核心迁移路径中移除，或明确放到独立实验工具而不能伪装成原版迁移。

处理结论：已完成。独立 validator 及其非原版 CLI 已删除，迁移入口继续使用原版 driver 的阶段顺序。

## 三、Source Identification 偏差

### 4. 候选 Source 的识别范围扩大

| 原版 | 当前迁移实现 | 前因 | 后果 |
|---|---|---|---|
| Python AST 第一阶段只识别预设 LLM 客户端实例及其属性；第二阶段只追踪这些客户端属性的使用。 | `analyze_typescript_sources.js` 扫描 `.ts`、`.tsx`、`.js`、`.jsx`、`.mjs`、`.cjs`；按包名、通用方法名和文本关键词识别候选。 | 试图用通用规则覆盖 TypeScript 生态中的不同 SDK。 | 普通 `call`、`create`、`run`、`chat` 等方法可能被纳入候选，Source 集合扩大，结果不再等价。 |

处理结论：采用语义对等迁移。使用官方 TypeScript Compiler API 和 `TypeChecker`，从已知 TypeScript LLM SDK 的导入符号、客户端构造器或明确 API 符号出发，追踪其赋值、别名和使用关系，再定位候选函数；随后继续由原版 Source 确认阶段判断该函数是否返回 LLM 输出。不得使用“文件中存在 LLM 包”加通用方法名、变量文本关键词或其它无对象关联的兜底匹配。允许按照 TypeScript 的语言结构调整符号追踪方式，但不得改变“已知 LLM 客户端/API -> 使用位置 -> 候选函数 -> LLM 确认”的 high-level 语义和下游结果契约。

具体共识与实现边界：

- 高层主链固定为“精确定位 LLM 对象/API -> 精确定位其使用位置 -> 定位包含使用位置的函数 -> LLM 确认函数是否调用 LLM 且返回模型输出”。候选发现不直接决定最终 Source。
- TypeScript 前端应先读取目标的 `tsconfig.json` 建立 `Program` 与 `TypeChecker`；没有配置时才以发现的目标源码建立基础 `Program`。只分析目标源码，排除依赖、声明文件和构建产物。
- SDK 表是 Python `llm_client_keywords` 的语言对等物。每项以包来源和导出符号精确登记客户端构造器、客户端类型、工厂函数或直接模型调用函数；导入别名、re-export 和 CommonJS 导入均须解析到实际符号。仅导入某个包不能产生候选。
- 对象识别与使用追踪按 TypeScript 语法适配：覆盖类字段和 `this` 属性、构造器参数属性、模块级变量、函数局部变量、明确的别名赋值、可选链和解构后的已确认引用；别名传播仅沿可证明的符号赋值关系迭代，不以变量名推测。
- 直接函数式 SDK API（例如已登记包导出的模型调用函数）可以作为初始 API 种子；调用接收者或被调用函数必须可追溯到该精确符号。工厂创建的 Agent/Executor 只有在具体 SDK 条目明确登记了从模型到返回对象的传播语义时才继续追踪，不能按 `agent`、`model` 等名称泛化。
- 对每个确认使用记录完整来源链、模块/类/函数、参数、函数范围和使用位置；扫描阶段保留每个使用位置，仍由原版确认阶段按函数标识去重并输出原有结构化结果。TypeScript 确认 Prompt 只替换语言表述，继续要求“调用 LLM 且返回其输出”。

### 5. TypeScript 候选去重改变结果数量

原版按属性使用记录处理；当前脚本用 `file:start:end` 去重。同一函数内多个不同 LLM 调用只保留一个候选，可能丢失原版会分别处理的 Source 记录。

处理结论：已完成。TypeScript 扫描保留每个实际使用记录，函数级去重仍由 `confirm_source.py` 执行。

### 6. Source 确认后的定位信息没有真正用于 CodeQL 匹配

| 原版 | 当前迁移实现 | 前因 | 后果 |
|---|---|---|---|
| Pysa Source 文件使用完整模块、类、函数和参数签名定位具体函数。 | `make_pysa_source.py` 的 CodeQL 分支只把确认记录的 `attribute` 合并进全局 `call_names`；生成器没有按 `full_method_path`、模块或类建立精确谓词。 | 为快速复用原 Source 生成入口，将 CodeQL 模型简化为方法名匹配。 | 某个函数确认成功后，同名方法可能在整个项目中都被视为 Source，造成明显过报。 |

处理结论：CodeQL Source 谓词只能使用 LLM 已确认结果中的项目内具体函数身份匹配调用，并将该调用的返回值标记为 `LLMControlled`。匹配至少保留模块/文件、类、函数和源码范围或其经 `TypeChecker` 解析后的等价符号身份；不得把 `full_method_path` 等定位信息降级为全局裸方法名匹配。

### 7. Source 模型退化为通用属性名匹配

当前 `taintp2x_models.json` 把 `content`、`text`、`response`、`output`、`customToolSchema` 等属性作为全局 Source。原版是具体库和具体 API 的返回值模型，不是任意同名属性。结果是非 LLM 数据也可能被标为 `LLMControlled`。

处理结论：删除全部全局属性名 Source。CodeQL 只能依据已确认的具体 LLM API/函数调用标记 Source；若某个 SDK 必须经 `content`、`text` 等返回对象字段取得模型输出，应在该具体 API 的局部语义中表达，不得将字段名全局化。

### 8. `FromUrlLLMControlled` 的约束丢失

原版 `taint.config` 有 URL 正则隐式 Source，要求匹配特定 LLM endpoint 形态。当前模型把所有 `fetch`、`request`、`get`、`post` 以及 `url`、`endpoint` 属性纳入 Source，没有保留 URL 约束，普通网络请求会被扩大为 LLM Source。

处理结论：保持它在原版中的小范围补充 Source 定位，不将其扩展为通用 HTTP 或 URL Source。删除 `fetch`、`request`、`get`、`post` 及 `url`、`endpoint` 的全局匹配，在 CodeQL 中对 TypeScript/JavaScript 静态字符串字面量应用原版正则 `^https://[^/]*/chat`，匹配后保留独立的 `FromUrlLLMControlled` 类型及其对应规则。无插值模板字符串可以按静态字符串处理，含插值的动态模板不纳入该规则。

限制说明：该原版正则只匹配域名后直接以 `/chat` 开始的 URL，例如 `https://example.com/chat`；不能匹配 `https://api.openai.com/v1/chat/completions` 等域名后先出现 `/v1` 的 URL。此处只如实迁移原版能力，不借语言迁移扩大覆盖范围。

## 四、Sink、Transform 和规则语义偏差

### 9. Sink 从精确参数变成同名函数的任意参数

原版 Pysa 模型针对具体模块、类、函数和参数位置标注 Sink，例如 `exec` 的特定参数、`subprocess` 的 `args`/`env`、数据库 API 的 SQL 参数。当前 CodeQL 生成器大量使用 `call.getAnArgument()`，导致任意同名函数的任意参数都可能命中 Sink。`query`、`run`、`send`、`write`、`parse` 等通用名称尤其容易产生大量误报。

### 10. `ExecEnvSink` 语义改变

原版将 `env` 作为命令执行 API 的特定参数。当前实现把任意属性读取 `env` 或 `envs` 作为 Sink，脱离了调用上下文和参数语义。

处理结论（第 9、10 项）：按照原版 Sink 类别，为 TypeScript 选择具有相同安全语义的 API，并在 CodeQL 中精确限定包、导出符号、调用对象和具体参数位置。没有 TypeScript 语义对应物的 Python API 不迁移；不得使用裸方法名、任意参数或全局属性名进行近似匹配。`ExecEnvSink` 只能标记命令执行 API 中承载环境变量的对应参数，不能匹配普通对象的 `env`/`envs` 属性。

### 11. Sanitizer 语义扩大

原版 Sanitizer 由 Pysa 模型、函数签名和既有污点类型共同决定。当前仅按方法名匹配 `escapeHtml`、`sanitizeHtml`、`sanitize`、`DOMPurify`，没有限定库、调用对象、参数或返回值，可能把普通辅助函数当成 Sanitizer。

处理原则：删除当前新增的 `escapeHtml`、`sanitizeHtml`、`sanitize`、`DOMPurify` 等通用 Sanitizer，不建立原版不存在的 Sanitizer 名单。实现迁移时再结合原版 `pathlib.Path.write_text`/`write_bytes` 的 Pysa 注解语义、TypeScript 对应文件 API 的实际行为以及 CodeQL 官方数据流模型，判断是否存在能够证明语义对等的表达；若 CodeQL 的实际传播不需要额外阻断，或找不到可靠的 TypeScript 对等语义，则不迁移该具体 Sanitizer，并明确记录原因，不能用裸方法名或近似规则补造功能。

### 12. FileOperation Transform 没有等价迁移

原版使用 `TaintInTaintOut[Transform[FileOperation]]` 表达文件操作的污点变换关系。当前只添加“文件操作调用的参数 -> 调用节点”的 CodeQL 额外流步骤。这不是同一语义，可能改变 Source 到文件相关 Sink 的传播路径和告警数量。

处理结论：`FileOperation` 是原版论文中的关键高层设计，必须进行严谨的语义对等迁移。迁移后继续将其表示为独立的污点状态，精确保留“受控文件位置进入文件操作、读取出的文件数据携带 `FileOperation` 状态继续传播”的边界，以及只有指定规则接受该状态的约束；不得降级为所有同名文件函数的任意参数到调用结果的普通流步骤。实现时优先依据 CodeQL 官方 `FileSystemReadAccess` 等文件系统语义抽象，逐个核对同步返回值、Promise 结果和 callback 数据参数等实际数据位置；没有可靠 TypeScript/CodeQL 对等语义的具体 API 不做近似匹配。

### 13. 隐式 Source 规则未迁移

原版 `taint.config` 中的 `implicit_sources.literal_strings` URL 规则没有对应的 CodeQL 实现，因此部分原版隐式 Source 行为在迁移后丢失。

该项与第 8 项相同，按第 8 项已经确定的方案合并处理。

### 14. 多条原版规则被合并为单一 CodeQL 规则

原版有多个规则码（如 5001、5002、5003、5008、5015 以及 `FromUrlLLMControlled` 对应的 600x 规则），每条规则拥有明确的 Source、Sink、Transform 和消息。当前统一输出 `taintp2x/dataflow`，并在查询头部固定 `CWE-094`、严重性 `9.8` 和 `medium`。

这不是单纯的后端格式转换：它丢失了原版规则码、漏洞类型、消息和规则级别的区分，也可能给不属于 CWE-94 的 Sink 强行附加同一个 CWE 元数据。

处理结论：原版规则表及每条规则的 Source、Sink、Transform、编号、名称和消息均属于分析语义，必须完整迁移。CodeQL 内部可以采用多条查询，或通过带状态的统一求解器严格求解后再映射，但允许的路径组合和最终规则身份必须与原版一致；不得退化成“任意 Source 到任意 Sink”。删除当前统一写死的 CWE-94、`security-severity 9.8` 和 `precision medium`。当前单一查询是针对测试用例的过拟合和 test hacking，不属于完整、对等的迁移实现，不能保留。

## 五、LLM 验证与结果契约偏差

### 15. SourceDeterminer 的职责改变

原版 SourceDeterminer 判断“候选函数是否请求 LLM API，并把 LLM 输出作为 Source”。当前 CodeQL 后验证路径中的 `confirm_codeql_finding` 判断“CodeQL 路径的 Source 是否攻击者可控”。这是新的判断问题，不是原版 Source 确认的语言迁移。

### 16. Source 判断结果没有控制后续流程

当前 `validate_codeql_results.py` 即使 Source 阶段返回否定结果，也会继续调用最终分析；原版 Source 阶段的结果会决定哪些 issue 进入后续 Fully 分析。因此当前 Source 判断只是附加信息，没有保留原版的流程控制作用。

处理结论（第 15、16 项）：完整保留扫描前 `confirm_source.py` 和扫描后 `SourceDeterminer` 两次 Source 确认。CodeQL SARIF 只替换 Pysa issue 的数据来源；后置 `SourceDeterminer` 仍从污点路径的第一个 Source 提取所在 TypeScript 函数，并判断它是否请求 LLM 对话 API，Prompt 只做语言与对应 API 示例的迁移。保留原版 `is_vulnerability` 字段及其在该阶段的实际含义；只有返回 `true` 的 issue 才能进入 `FullyDeterminer`。删除当前新增的“Source 是否是攻击者可控输入”判断及绕过门控继续分析的行为。

### 17. FullyDeterminer 的原有阶段被绕过

原版 FullyDeterminer 包含逐函数污点分析、重复函数去重、Sanitizer 实现补充、漏洞类型提示、整条调用链综合判断及结果保存。当前 CodeQL 后验证器只将 SARIF 位置上下文直接发给模型，未完整复用这些阶段。因此当前实现不是“把 Pysa trace 换成 CodeQL trace”，而是新的简化判断流程。

处理结论：当前实现没有保留原版步骤，也不是替换式迁移，必须收敛回原版 `FullyDeterminer`。完整保留调用链解析、路径函数源码提取、按函数实现去重、逐函数污点有效性与过滤判断、调用链外过滤函数实现补充、整条调用链综合判断以及结构化结果保存；只将 Pysa trace 输入替换为 CodeQL path，并将 Python 函数定位替换为 TypeScript Compiler API/符号定位。Prompt 只迁移语言描述，原判断任务、阶段顺序和 JSON 字段不变；不得以一次性提交 SARIF 位置上下文的新流程替代原实现。

### 18. 原版输出目录和中间文件契约被改变

原版验证流程使用 `issue_data.json`、`file_paths_and_lines.json`、`context_output.txt`、`response_output.json`、`trace_chain.log`、`analysis_results.json` 等中间文件，并支持已有 issue、重复路径和结果的复用。当前新增验证器输出单个 Markdown 报告，未保持这些文件和断点/合并契约。

处理结论：已完成。SARIF 适配器保留有序路径并生成原版 `taint-output.json`；两个验证阶段继续使用按项目/issue 的 `issue_data.json`、`file_paths_and_lines.json`、`context_output.txt`、`response_output.json`、`trace_chain.log` 和 `analysis_results.json`。未保留独立 Markdown 结果契约。

### 19. 原版漏洞类型字段丢失

原版 `FullyDeterminer` 会尝试从 SourceDeterminer 的 `response_output.json` 读取可选的 `vulnerability_types`，并为 `Code_Execution`、`SQL_Injection`、`File_Operation`、`XSS`、`SSRF` 加入对应分析提示；但 SourceDeterminer 的 Prompt 没有要求返回该字段，仓库中也不存在根据 Pysa 规则或 Sink 写入该字段的代码。因此原版实际状态是消费逻辑存在、明确生产链缺失，而不是稳定的输出契约。

处理结论：保留 `FullyDeterminer` 对可选 `vulnerability_types` 的读取、全部类型专用 Prompt 以及字段存在时的原有行为；不新增原版不存在的 CodeQL Sink/规则到 `vulnerability_types` 的生成逻辑，也不借迁移修复这一原版缺口。CodeQL 仍须保留准确的 Sink 和规则身份，但不得据此擅自补造字段生产链。文档应明确记录该字段在原版只有消费端、没有明确生产端。

### 20. LLMClient 调用参数语义改变

原版验证器通过 `chat_completion` 传入 `messages`、`temperature`、`max_tokens` 和 `response_format`。当前兼容方法把多条消息拼接成单个字符串，并忽略传入的模型调用参数，统一使用 `complete` 的固定请求配置，改变了原模型调用接口行为。

处理结论：`LLMClient.chat_completion` 仅作为透明的远程 LLM 通信适配层。Prompt、函数源码、污点路径、消息顺序和角色在构造完成后必须原样发送；原版中文 Prompt 严格对等翻译为英文属于 TypeScript 语言迁移，不视为内容改变。模型、端点、凭据和 provider 扩展参数只能来自运行配置，删除 `SourceDeterminer`、`FullyDeterminer` 等调用点中硬编码的 `deepseek-ai/DeepSeek-V3` 或其它模型名。通信层按实际远程协议传递、重命名或省略 `temperature`、token limit、`response_format`、thinking 等非内容参数，并可将响应协议外壳规范化为原版调用方期望的结构，但不得改写模型正文。删除当前拼接全部消息并忽略调用参数的实现；不为这一直接约束额外增加内容对比验证流程。

## 六、配置、环境和文档问题

### 21. 迁移配置加入了新的实验控制面

`TYPESCRIPT_REPRODUCTION_CONFIG.json` 引入 CodeQL CLI、QL pack、数据库、生成模型、超时和安装命令等字段。CodeQL CLI、数据库路径和安装命令是替换后端所需的环境配置；但如果这些字段被用于改变分析流程、筛选结果或扩展模型判断，就超出配置职责。配置应只描述运行环境和目标项目，不承担新的研究逻辑。

处理结论：当前配置中没有条目筛选、分类切换、跳过原版阶段等额外分析控制，因此不删除现有目标、环境、依赖安装、CodeQL 后端和远程 LLM 配置，只增加约束：配置只能描述目标、运行环境和后端位置，不能改变 Source/Sink/Transform/规则语义、筛选结果或启用额外实验流程。模型、端点和通信参数必须来自配置或环境，代码内不得硬编码。TypeScript 迁移分支最终直接使用仓库已有的 `REPRODUCTION_CONFIG.json` 名称，并删除重复的 `TYPESCRIPT_REPRODUCTION_CONFIG.json`，不在配置文件名前增加语言前缀。

### 22. 文档曾把扩展功能描述为迁移结果

`REPRODUCTION_GUIDE.md` 曾把三类新增分类及其统计写成 TypeScript 迁移的复现结果。当前工作树已改为原版 `is_vulnerability` 契约，但文档和历史 artifact 需要与最终修正版代码一起重新核对，不能继续引用旧分类统计。

处理结论：已完成初步核对。指南当前使用 `config.json`、规则目录和原版验证入口；最终交付前仍需从干净 `.workspace` 重跑一次，以核对命令、路径和实际 artifact。

## 七、结论和修正状态

本次审计列出的迁移偏差已按以下原则处理：

1. 不生成研究用的 `LLM-in-the-Loop`、`traditional`、`Not-Sure` 分类。
2. CodeQL SARIF/path 通过兼容适配器进入原版 `SourceDeterminer` 和 `FullyDeterminer`，没有独立 validator 流程。
3. Source、Sink、Transform、隐式 URL Source、规则编号和消息按可证明的 TypeScript/CodeQL 语义迁移；没有可靠对等语义的 Python 专用能力明确保持为空。
4. Source/Sink 使用项目函数身份、官方安全概念和精确调用上下文，不使用全局通用名称兜底。
5. LLM 通信保留消息顺序、角色和调用方参数，模型、端点和凭据全部由运行时配置提供。
6. 验证阶段保留原版 issue 目录和中间文件契约；最终干净工作区复现只用于核对环境差异和文档，不改变分析语义。

### 可以保留

- TypeScript Compiler API 作为 Python AST 的语言替代。
- CodeQL 作为 Pysa 的后端替代。
- Node/TypeScript Docker 镜像。
- CodeQL 数据库和 SARIF 作为后端 artifact，但需要通过兼容适配层接入原版验证流程。
- 运行时配置和目标依赖安装步骤，只要不改变分析语义。

### 当前修正状态

当前关键代码修正已提交；剩余工作仅是干净工作区的最终复现和文档结果核对，不再引入新的分析逻辑。
