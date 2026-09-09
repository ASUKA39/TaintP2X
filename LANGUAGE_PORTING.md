# TaintP2X 语言移植分析

本文档分析 TaintP2X 的语言耦合程度，重点说明 Pysa 与 TaintP2X 之间的驱动关系，并讨论移植到 TypeScript 和 Rust 时哪些部分可以复用、哪些部分需要替换。本文档只描述现有仓库，不代表已经实现了多语言支持。

## 结论

TaintP2X 不是对 Pysa 引擎源码的 fork，也没有在仓库内实现一套独立的污点分析引擎。它通过命令行启动外部 Pyre/Pysa，并向 Pysa 提供模型文件、配置、stub 和目标 Python 源码，再读取 Pysa 的 JSON 结果进行 LLM 验证。

因此两者的关系应拆成两层理解：

- **分析引擎层：外部驱动关系。** TaintP2X 调用 `pyre analyze`，Pysa 负责类型环境、跨函数污点传播和候选路径输出。
- **模型与数据管线层：深度耦合关系。** TaintP2X 的 source 识别、sink 定义、Python 库 stub、模型生成、结果解析和 LLM 后验证都围绕 Pysa 的模型语法、Python 程序模型和 Pysa 输出格式组织。

所以称 TaintP2X 是“Pysa 的 wrapper”只对引擎调用层成立；从整体工具看，它是一个高度 Python/Pysa 特化的外围分析管线。

## TaintP2X 如何驱动 Pysa

核心入口是 [`run_download_and_check.py`](run_download_and_check.py)。对每个目标仓库，当前流程大致如下：

```text
克隆目标仓库
  → Python AST 扫描
  → LLM 确认哪些函数产生/返回 LLM 输出
  → 生成项目专属 .pysa source 模型
  → 写入 Pyre 配置
  → 执行 pyre analyze
  → 读取 taint-output.json
  → LLM 验证 source、污点传播和可利用性
```

### Pysa 是外部进程，不是库内模块

TaintP2X 通过以下命令启动 Pysa：

```bash
pyre analyze --no-verify --save-results-to <output_dir>
```

仓库中没有 Pyre/Pysa 的引擎源码，也没有对其污点传播算法的修改。`TaintP2X` 本身不计算跨函数污点闭包，实际传播由 Pysa 完成。

### TaintP2X 注入给 Pysa 的输入

运行前，脚本动态写入 `Taint_Propagation/.pyre_configuration`，主要配置包括：

```json
{
  "source_directories": ["<目标仓库>"],
  "taint_models_path": [
    "./Taint_Propagation/taint",
    "<目标仓库>/source"
  ],
  "search_path": [
    "./Taint_Propagation/stubs"
  ]
}
```

Pysa 随后读取以下几类输入：

1. 目标仓库中的 Python 源码；
2. `Taint_Propagation/taint/` 中预定义的 `.pysa` 模型；
3. 运行时生成的项目专属 `.pysa` 文件；
4. `Taint_Propagation/stubs/` 中的 Python `.pyi` 库桩；
5. `Taint_Propagation/taint/taint.config` 中定义的 source、sink 和规则。

### source 是如何接入 Pysa 的

[`Source_Identification/analyze_assignments.py`](Source_Identification/analyze_assignments.py) 使用 Python `ast` 扫描目标仓库，识别 `OpenAI`、`Anthropic`、`Groq` 等客户端实例及其属性使用。

[`Source_Identification/confirm_source.py`](Source_Identification/confirm_source.py) 再将方法源码交给 LLM，确认方法是否真正请求并返回 LLM 输出。

[`Source_Identification/make_pysa_source.py`](Source_Identification/make_pysa_source.py) 把确认结果转换成 Pysa 模型，例如：

```python
def package.Class.method(...) -> TaintSource[LLMControlled]: ...
```

这个生成的 `.pysa` 文件不是 TaintP2X 自己解释的中间格式，而是直接交给 Pysa 加载。因此，Pysa 的模型语法是 TaintP2X source 识别阶段和静态传播阶段之间的实际接口。

### sink 和传播规则是如何接入 Pysa 的

TaintP2X 预先维护 Python API 的 sink 模型，例如：

- `eval`、`exec`、`os.system`、`subprocess`；
- `pickle`、`yaml` 等反序列化函数；
- `open`、`pathlib`、压缩包和文件系统 API；
- SQL 执行函数；
- HTTP 请求、响应头、日志、邮件和 XSS 输出。

这些模型使用 Pysa 的 `TaintSink[...]`、`TaintSource[...]`、`TaintInTaintOut`、`Sanitize`、`ViaValueOf` 等标注表达 source、sink、传播、净化和附加标签。例如：

```python
def subprocess.run(
    args: TaintSink[ExecArgSink],
    ...
): ...
```

`taint.config` 再把 `LLMControlled` 等 source 与具体 sink 组合为规则。规则的闭包计算、跨函数传播和路径形成仍由 Pysa 完成。

## TaintP2X 自己实现的部分

### 1. 目标仓库获取和任务调度

脚本负责读取 `test_source.json`、克隆仓库、设置超时、记录 `checked_repos.json`，并把不同仓库的分析任务提交到线程池。

### 2. Python AST source 候选发现

TaintP2X 不是让 Pysa 自动发现任意 LLM API，而是先用 Python AST 启发式定位客户端赋值、类继承和属性使用，再把候选方法交给 LLM。

这里直接使用了 Python 特有结构：

- `ast.ClassDef`、`ast.FunctionDef`、`ast.AsyncFunctionDef`；
- Python 装饰器、`self.attribute` 和字典下标赋值；
- Python 方法参数和嵌套函数命名；
- `.py` 文件和 `ast.unparse`。

### 3. 模型文件生成

TaintP2X 将 LLM 结果翻译成 `.pysa` 文本。它没有抽象的语言无关 source/sink IR；生成目标就是 Pysa 的 Python 模型语言。

### 4. Pysa 结果解析和代码回收

TaintP2X 读取 `taint-output.json`，提取 issue、source、文件路径、行号和调用链，再回到仓库中取代码片段。

验证器中存在明显的 Python 假设：

- 只搜索 `.py` 文件；
- 通过 `def ` 或 `async def ` 判断函数起点；
- 通过缩进判断函数结束；
- 将 Python 模块路径转换为点分隔的函数路径；
- 假定 Pysa 的 issue/trace JSON 结构。

### 5. LLM 后验证

Pysa 输出的是候选污点路径，不是最终漏洞结论。TaintP2X 的 `SourceDeterminer` 和 `FullyDeterminer` 会再次让 LLM 判断：

- source 是否确实是 LLM 输出；
- 污点传播是否有效；
- 是否存在过滤/净化；
- sink 是否真的能触发目标安全影响。

这部分可以保留方法论，但输入代码的提取方式和调用链格式仍依赖 Python/Pysa。

## 耦合关系分层

| 部分 | 与 Pysa 的关系 | 与 Python 的关系 | 移植影响 |
|---|---|---|---|
| Pyre/Pysa 引擎 | 外部 CLI 调用，未修改引擎 | 间接依赖 | 可替换，但需要新后端协议 |
| `.pysa` source/sink 模型 | 直接依赖 Pysa 模型语言 | 强依赖 Python 函数/模块模型 | 必须重建 |
| `.pyi` 库桩 | 由 Pysa 加载 | 强依赖 Python 包和签名 | 必须重建 |
| `taint.config` 规则 | 使用 Pysa source/sink 标签 | source/sink 名称对应 Python API | 规则概念可复用，语法需重写 |
| AST source 发现 | 不属于 Pysa | 强依赖 Python AST | 必须重写 |
| Pysa JSON 解析 | 依赖 Pysa 输出结构 | 代码定位依赖 Python | 需要适配新输出 |
| LLM 验证 Prompt | 相对独立 | 输入代码和调用链仍是 Python 格式 | 可部分复用 |
| 仓库调度和结果目录 | 外围逻辑 | 基本语言无关 | 大多可复用 |

## 替换 Pysa 时真正需要保持的接口

如果将 Pysa 替换为其他 SAST，不能只替换一条命令。TaintP2X 当前依赖的实际接口至少包括：

1. **source 建模接口**：能够把指定的 LLM API 返回值标为 `LLMControlled`；
2. **sink 建模接口**：能够把命令执行、文件、SQL、网络、反序列化等参数标为不同安全类别；
3. **传播接口**：能够进行跨函数、跨模块的污点传播，并支持必要的 summary/propagator；
4. **路径结果接口**：能够返回 source、sink、中间调用位置和源码行号；
5. **净化接口**：能够表示 sanitizer 或至少让后处理区分被过滤的路径；
6. **可扩展库模型接口**：能够补充第三方 LLM SDK 和应用框架 API；
7. **稳定的机器可读输出**：结果需要能被后续 LLM 验证阶段消费。

Pysa 的价值不只是“运行 taint analysis”，而是同时提供了 Python 类型环境、`.pyi` 库桩、`.pysa` 模型语言、规则配置和结构化 trace。替换后端时，这些能力需要由新工具分别提供，或者由 TaintP2X 自己增加适配层。

## 移植到 TypeScript

### 可以保留的部分

- “LLM 输出作为 source”的研究定义；
- source → sink 的安全类别划分；
- 先静态筛选、再由 LLM 验证的两阶段流程；
- 仓库处理、任务调度、结果汇总和大部分 Prompt；
- source/sink/propagator/sanitizer 这组抽象概念。

### 需要替换的部分

TypeScript 不能使用 Pysa，因为 Pysa 的模型语言和程序模型面向 Python。需要重写：

- Python AST 扫描，改为 TypeScript/JavaScript AST 或目标 SAST 的程序模型；
- `.pysa` source/sink 模型，改为新工具的规则或查询；
- 207 个 Python `.pyi` stub，改为 npm/Node.js/TypeScript 库模型；
- LLM SDK source，例如 OpenAI、Anthropic、LangChain、Vercel AI SDK 等 Node.js 调用形式；
- Node.js 的 `child_process`、文件系统、HTTP、数据库、模板和反序列化 sink；
- Promise、`async/await`、callback、EventEmitter、动态属性和动态 import 的传播；
- Pysa JSON trace 解析和 Python 缩进式函数提取。

TypeScript 的后端可以选择支持 JavaScript/TypeScript 的 CodeQL 或 Semgrep 等工具，但需要重新实现 TaintP2X 的模型生成器和结果适配器。对 TaintP2X 来说，最接近 Pysa 的替代是能够提供自定义 source/sink、跨函数传播、sanitizer、propagator 和路径输出的 CodeQL JavaScript/TypeScript 查询；这仍然是“换后端并重建模型”，不是直接转换 `.pysa` 文件。

TypeScript 移植的主要风险是 JavaScript 动态特性、转译与 Source Map、Promise/事件驱动控制流，以及第三方 SDK 的多种调用封装。总体上可行，但属于静态后端级移植。

## 移植到 Rust

### 可以保留的部分

- 漏洞类别和 `LLMControlled` source 的概念；
- source/sink/propagator/sanitizer 的高层数据结构；
- LLM 辅助确认和结果报告流程；
- 仓库调度与实验框架。

### 需要替换的部分

Rust 没有 Pysa 对应的模型生态，需要重新建立：

- Rust AST/语义索引；
- LLM SDK 和 crate API 的 source 模型；
- `std::process::Command`、文件系统、网络、SQL、模板和 `serde` 等 sink 模型；
- trait、generic、ownership、borrowing、lifetime 和 async Future 的跨函数传播；
- macro expansion、build script 和生成代码的位置映射；
- Rust 函数、trait method、模块和 crate 的代码提取；
- 新 SAST 的结构化路径输出。

即使使用支持 Rust 的 SAST，也需要重新定义模型和路径适配。Rust 的难点不是把 Python 模型文件改写成另一种语法，而是缺少与 Pysa `.pyi/.pysa` 体系等价的现成模型库，以及更复杂的语言语义。总体上属于高成本后端重建。

## 当前实现层面的注意事项

现有驱动脚本还暴露出一些会影响实验复现的工程问题：

- 多线程任务共享并覆盖同一个 `Taint_Propagation/.pyre_configuration`；
- `taint_models_path` 中保留了字面量 `{folder}/source`，并非所有路径都被格式化；
- Pysa 结果目录和目标仓库目录由脚本拼接管理，后续 LLM 阶段依赖这些固定路径；
- 当前若干验证脚本存在语法、接口或 Python import 问题，不能把仓库结构直接等同于一条已经稳定可运行的端到端管线。

这些问题不改变 Pysa 与 TaintP2X 的架构关系，但在比较替代 SAST 时需要区分：哪些是研究设计，哪些只是当前脚本实现。

## 总结

TaintP2X 在 Pysa 之上构建的不是新的污点传播引擎，而是一个围绕 Pysa 模型接口和输出格式组织的 Python 分析系统：

```text
Python AST/LLM source 识别
  → 生成 .pysa 模型
  → Pysa 负责静态污点传播
  → 解析 Pysa trace
  → LLM 做 source/路径/可利用性验证
```

因此：

1. **Pysa 引擎可以被替换**，因为 TaintP2X 通过外部 CLI 驱动它，没有修改其内部实现。
2. **替换成本仍然很高**，因为 TaintP2X 的模型生成、Python stub、source/sink 语义和结果解析深度依赖 Pysa 与 Python。
3. **TypeScript** 可以复用整体研究流程，但需要换成 TypeScript SAST，并重建所有语言模型和适配器。
4. **Rust** 需要重建更多语言语义和库模型，移植成本显著高于 TypeScript。

