# TaintP2X Python Baseline Reproduction

## 前置条件

在 TaintP2X 根目录执行本指南。需要 Docker（支持 `linux/amd64` 镜像运行）、可访问 GitHub 和模型 API 的网络，以及能够执行 Bash 命令的终端。`REPRODUCTION_CONFIG.json` 提供容器名、目标仓库、固定版本、目标导入名和依赖安装命令；尖括号字段是替换为该配置值的占位符。

本指南假定 `.workspace/` 是本次实验的全新 artifact 目录。若重复运行同一个示例，先确认没有需要保留的结果，再删除本示例的精确目录：

```bash
rm -rf .workspace/project-sources/vanna-ai__vanna__v0.3.4 \
       .workspace/dependency-install/vanna-ai__vanna__v0.3.4.log \
       .workspace/pysa-analysis/vanna-ai__vanna__v0.3.4
```

不要删除整个 `.workspace/`，其中可能包含其他实验结果。

## 示例测试目标

本指南使用 `vanna-ai/vanna` 作为原版 Python TaintP2X 的测试目标。

- 仓库：`https://github.com/vanna-ai/vanna`
- 测试版本：`v0.3.4`
- 漏洞编号：`CVE-2024-5826`
- CWE：`CWE-94`
- CVSS：`9.8`
- 漏洞表来源：`results/cve_ghsa_repository_matches.csv`

漏洞表中的描述是：攻击者可以通过 `vanna.ask` 进行 prompt injection，使 LLM 生成的代码最终传入 `src/vanna/base/base.py` 中的 `exec` 执行，造成远程代码执行。漏洞记录的受影响版本未固定到某个明确版本；本指南选择 `v0.3.4` 作为固定复现版本，并以源码中的实际调用链验证扫描结果。

该条目符合 TaintP2X 的作用范围：TaintP2X 将 LLM API 输出建模为 `LLMControlled` Source，并将 Python `exec` 建模为远程代码执行 Sink。该漏洞的预期利用链是 LLM 输出到 `exec`，因此可作为原版 Python 检测流程的示例目标。

## Step 1：构建 Python baseline Docker 镜像

在 TaintP2X 根目录执行：

```bash
docker build --platform linux/amd64 -t taintp2x:baseline .
```

镜像由仓库根目录的 `Dockerfile` 定义，使用 Ubuntu 22.04，安装 Python 3.10、编译工具和 Git，并在 `/opt/venv` 创建隔离 Python 环境。镜像内固定安装 Pyre/Pysa 0.9.23，以及从 `facebook/sapp` 固定 commit `4c3d3086cbf447ec5cd53ea654751735c2c5f973` 安装的 SAPP CLI；同时安装 TaintP2X 当前脚本直接导入的 `requests`、`openpyxl`、`openai`、`zhipuai` 和 `tqdm`。

验证镜像和工具：

```bash
docker image inspect taintp2x:baseline

docker run --rm --platform linux/amd64 taintp2x:baseline bash -lc '
  python --version
  pyre --version client_and_binary
  sapp --help >/dev/null && echo sapp-cli-ok
  python -c "import openai, openpyxl, requests, zhipuai; print(\"imports-ok\")"
'
```

本次复现已验证输出包含 `Python 3.10.12`、`Client version: 0.9.23`、`sapp-cli-ok` 和 `imports-ok`。该步骤只建立并验证工具镜像，不 clone 或安装测试目标仓库，也不运行 TaintP2X 分析。

## TypeScript 迁移复现

本节记录 `typescript-port` 分支已经实际跑通的 TypeScript 检测链。TypeScript 和 JavaScript 使用 CodeQL 的统一 `javascript` extractor；CodeQL CLI 及官方 JavaScript QL pack 沿用 IRIS 的 `.workspace` checkout，通过只读挂载提供给 TaintP2X 容器。修复生成和运行时 exploit 均不执行，结果是静态 CodeQL SARIF。

### TypeScript 输入和 artifact 布局

通用配置文件是 `TYPESCRIPT_REPRODUCTION_CONFIG.json`，至少提供目标仓库 URL、固定 ref/commit、源码目录、CodeQL 数据库目录、查询路径、CodeQL CLI/QL pack 路径和目标依赖安装命令。所有源码、数据库、Source Identification 输出和 SARIF 均放在 `.workspace/`；镜像构建上下文不会复制 `.workspace`。

本次示例的目标是 `FlowiseAI/Flowise` 的 `2.2.6`（commit `da04289ecf1c25dc4894737e9d00eac9f6d9ec7d`），配置文件为 `TYPESCRIPT_REPRODUCTION_CONFIG.json`，源码目录为 `.workspace/project-sources/FlowiseAI__Flowise_CVE-2025-55346_2.2.6`，通用查询为 `CodeQL_Queries/TaintP2X.ql`。

### TypeScript Step 1：构建独立迁移镜像

通用命令：

```bash
docker build --platform linux/amd64 -f Dockerfile.typescript -t taintp2x:typescript .
docker run --rm --platform linux/amd64 taintp2x:typescript bash -lc '
  node --version
  tsc --version
  python --version
  python -c "import requests; print(\"python-runtime-ok\")"
'
```

`Dockerfile.typescript` 使用 Node 22、官方 TypeScript Compiler API 5.4.5 和隔离 Python 环境；它不包含目标仓库依赖，也不把 CodeQL CLI 固定复制进镜像。目标依赖按配置在目标准备阶段安装，CodeQL CLI/QL pack 按 IRIS 方式从宿主机 `.workspace` 只读挂载。

本次镜像构建成功，验证输出为 Node `v22.23.2`、TypeScript `5.4.5`、Python `3.11.2` 和 `python-runtime-ok`。

### TypeScript Step 2：准备 CodeQL CLI 和官方 QL pack

通用准备方式与 IRIS 相同：CodeQL CLI 使用 `2.23.2`，官方 CodeQL 源码 checkout 使用 `codeql-cli/v2.23.2`，二者分别放在 `.workspace/codeql-cli-2.23.2` 和 `.workspace/codeql-repo`。如果这两个目录已经由 IRIS 准备好，不需要重复下载。

```bash
mkdir -p .workspace/codeql-cli-2.23.2 .workspace/codeql-repo
curl -L -o .workspace/codeql-cli-2.23.2/codeql.zip \
  https://github.com/github/codeql-cli-binaries/releases/download/v2.23.2/codeql.zip
unzip -qo .workspace/codeql-cli-2.23.2/codeql.zip -d .workspace/codeql-cli-2.23.2
rm -f .workspace/codeql-cli-2.23.2/codeql.zip
git clone --depth 1 --branch codeql-cli/v2.23.2 \
  https://github.com/github/codeql.git .workspace/codeql-repo
.workspace/codeql-cli-2.23.2/codeql/codeql version
git -C .workspace/codeql-repo describe --tags --exact-match
```

本次测试直接复用了 `/data/AgentSecStudy/tools/iris/.workspace/codeql-cli-2.23.2` 和 `/data/AgentSecStudy/tools/iris/.workspace/codeql-repo`，在容器中分别挂载为 `/taintp2x/.workspace/codeql-cli-2.23.2` 和 `/taintp2x/.workspace/codeql-repo`；CLI 版本校验为 `2.23.2`。

### TypeScript Step 3：获取并固定目标源码

通用命令：

```bash
PROJECT_DIR=".workspace/project-sources/<TARGET_NAME>"
mkdir -p .workspace/project-sources
git clone --branch <REF> --depth 1 <REPO_URL> "$PROJECT_DIR"
test "$(git -C "$PROJECT_DIR" rev-parse HEAD)" = "<EXPECTED_COMMIT>"
```

本次目标已经获取并固定：

```bash
TARGET_DIR=".workspace/project-sources/FlowiseAI__Flowise_CVE-2025-55346_2.2.6"
test "$(git -C "$TARGET_DIR" rev-parse HEAD)" = \
  "da04289ecf1c25dc4894737e9d00eac9f6d9ec7d"
```

### TypeScript Step 4：准备目标依赖

目标仓库若需要依赖或构建，使用 `TYPESCRIPT_REPRODUCTION_CONFIG.json` 中的 `install_command` 和 `build_command`，在目标源码根目录执行；CodeQL JavaScript/TypeScript extractor 对本次 Flowise 数据库不要求先完成项目构建，因此建库测试不依赖 `pnpm install`。后续要分析依赖解析或生成构建产物时，再执行配置中的 `pnpm install --frozen-lockfile`。

本次示例配置的依赖命令为：

```bash
cd .workspace/project-sources/FlowiseAI__Flowise_CVE-2025-55346_2.2.6
corepack enable
corepack prepare pnpm@9.15.5 --activate
pnpm install --frozen-lockfile
```

### TypeScript Step 5：用官方 TypeScript Compiler API 识别 Source 候选

通用命令：

```bash
docker run --rm --platform linux/amd64 --user "$(id -u):$(id -g)" \
  --mount type=bind,src="$PWD",dst=/taintp2x \
  --workdir /taintp2x taintp2x:typescript bash -lc \
  'node Source_Identification/analyze_typescript_sources.js \
    <SOURCE_DIR> <SOURCE_DIR>/source/analysis_source_<TARGET_NAME>.json'
```

`Source_Identification/analyze_typescript_sources.js` 使用官方 Compiler API 遍历 `.ts`、`.tsx`、`.js` 和 `.jsx` AST，输出与 Python 管线兼容的 `assignments`、`attribute_uses`，同时保留模块、函数源码和行号。候选识别只负责定位可能的模型 SDK 调用，不把候选直接当成最终 Source。

本次示例命令：

```bash
docker run --rm --platform linux/amd64 --user "$(id -u):$(id -g)" \
  --mount type=bind,src="$PWD",dst=/taintp2x \
  --workdir /taintp2x taintp2x:typescript bash -lc \
  'node Source_Identification/analyze_typescript_sources.js \
    .workspace/project-sources/FlowiseAI__Flowise_CVE-2025-55346_2.2.6 \
    .workspace/project-sources/FlowiseAI__Flowise_CVE-2025-55346_2.2.6/source/analysis_source_FlowiseAI__Flowise_CVE-2025-55346_2.2.6.json'
```

本次扫描输出 81 个 TypeScript Source 候选，结果文件为 `.workspace/project-sources/FlowiseAI__Flowise_CVE-2025-55346_2.2.6/source/analysis_source_FlowiseAI__Flowise_CVE-2025-55346_2.2.6.json`。

### TypeScript Step 6：模型确认并生成 CodeQL Source 清单

通用确认命令：

```bash
docker run --rm --platform linux/amd64 --user "$(id -u):$(id -g)" \
  --mount type=bind,src="$PWD",dst=/taintp2x \
  --workdir /taintp2x \
  -e OPENAI_API_KEY="$OPENAI_API_KEY" \
  -e OPENAI_BASE_URL="https://api.deepseek.com" \
  -e OPENAI_MODEL="deepseek-v4-flash" \
  -e OPENAI_EXTRA_BODY='{"thinking":{"type":"disabled"}}' \
  taintp2x:typescript bash -lc \
  'python -m Source_Identification.confirm_typescript_source \
    <SOURCE_DIR> [--limit <N>]'
```

确认阶段沿用 `Source_Identification/llm_client.py` 的 OpenAI-compatible 适配；适配代码仍在该文件，替换其他远程模型时只需调整环境变量或该通用请求适配。确认完成后，`make_codeql_sources.py` 将 `is_llm_call=true` 的记录输出成可审计 Source 清单。

本次测试使用 DeepSeek 官方 API（`https://api.deepseek.com`、模型 `deepseek-v4-flash`、thinking disabled），对 3 个候选进行了实际确认，生成：

```text
.workspace/project-sources/FlowiseAI__Flowise_CVE-2025-55346_2.2.6/source/llm_analysis_FlowiseAI__Flowise_CVE-2025-55346_2.2.6.json
.workspace/project-sources/FlowiseAI__Flowise_CVE-2025-55346_2.2.6/source/codeql_sources.json
```

### TypeScript Step 7：创建数据库并运行 CodeQL 检测

CodeQL 数据库使用 `--language javascript`，因为 CodeQL 对 JavaScript 和 TypeScript 共用 extractor。通用命令如下，CLI 和 QL pack 通过只读挂载提供：

```bash
docker run --rm --platform linux/amd64 --user "$(id -u):$(id -g)" \
  --mount type=bind,src="$PWD",dst=/taintp2x \
  --mount type=bind,src="<CODEQL_CLI_CHECKOUT>",dst=/taintp2x/.workspace/codeql-cli-2.23.2,readonly \
  --mount type=bind,src="<CODEQL_REPO_CHECKOUT>",dst=/taintp2x/.workspace/codeql-repo,readonly \
  --workdir /taintp2x taintp2x:typescript bash -lc \
  'python scripts/run_typescript_codeql.py --config TYPESCRIPT_REPRODUCTION_CONFIG.json'
```

`scripts/run_typescript_codeql.py` 会在已有 Source Identification artifact 时跳过确认阶段，从 `CodeQL_Models/taintp2x_models.json` 生成 `CodeQL_Queries/TaintP2XModels.qll`，按配置创建数据库，最后执行固定的 `CodeQL_Queries/TaintP2X.ql` 并写出 SARIF。查询只实现一次通用 Source → Sink 连通性求解；API、Source、Sink、Sanitizer 和传播规则均来自模型清单，不依赖仓库名或具体 CVE。

本次实际运行使用：

```bash
docker run --rm --platform linux/amd64 --user "$(id -u):$(id -g)" \
  --mount type=bind,src="$PWD",dst=/taintp2x \
  --mount type=bind,src="/data/AgentSecStudy/tools/iris/.workspace/codeql-cli-2.23.2",dst=/taintp2x/.workspace/codeql-cli-2.23.2,readonly \
  --mount type=bind,src="/data/AgentSecStudy/tools/iris/.workspace/codeql-repo",dst=/taintp2x/.workspace/codeql-repo,readonly \
  --workdir /taintp2x taintp2x:typescript bash -lc \
  'python scripts/run_typescript_codeql.py \
    --config TYPESCRIPT_REPRODUCTION_CONFIG.json'
```

本次测试按配置重新创建了 `.workspace/codeql-dbs/FlowiseAI__Flowise_CVE-2025-55346_2.2.6` 数据库，输出 `.workspace/codeql-results/FlowiseAI__Flowise_CVE-2025-55346_2.2.6.sarif`。

### TypeScript 结果格式和校验

SARIF 是标准 JSON；`runs[0].results` 是告警列表，`codeFlows` 是可选的污点路径。校验命令：

```bash
jq '{count:(.runs[0].results|length), results:[.runs[0].results[]|{ruleId,message:.message.text,file:.locations[0].physicalLocation.artifactLocation.uri,line:.locations[0].physicalLocation.region.startLine}]}' \
  .workspace/codeql-results/FlowiseAI__Flowise_CVE-2025-55346_2.2.6.sarif
```

本次通用查询输出 72 条跨类别告警，其中包含 `LLMControlled → RemoteCodeExecution` 到 `packages/components/nodes/tools/CustomTool/CustomTool.ts:121` 的路径，即 `new Function('z', \`return ${customToolSchema}\`)`。查询本身不包含该仓库或该漏洞的专用逻辑；若需要新增 SDK 或 Sink，只修改模型清单并重新生成模型模块。

### TypeScript Step 8：LLM 后验证

CodeQL 只负责计算通用污点路径；后验证由 `scripts/validate_codeql_results.py` 完成。它读取 SARIF 的每条告警及全部 `codeFlows`，从目标源码提取路径位置上下文，使用配置的 OpenAI-compatible 模型判断攻击者入口、利用链、Sanitizer 和 `LLM-in-the-Loop`/`traditional`/`Not-Sure` 分类。该阶段是静态审计，不运行目标代码；模型调用失败的条目直接跳过，不伪造分类。

通用命令：

```bash
python scripts/validate_codeql_results.py \
  --sarif .workspace/codeql-results/<TARGET>.sarif \
  --source-root .workspace/project-sources/<TARGET> \
  --output .workspace/codeql-validation/<TARGET>.md \
  --workers 4
```

本次 Flowise 测试对包含 `RemoteCodeExecution` 的告警实际执行后验证，单条报告保存在 `.workspace/codeql-validation/flowise-retest.md`。随后去掉 `--contains` 对全部 72 条告警完成后验证，报告为 `.workspace/codeql-validation/flowise-retest-all.md`，成功后验证 72/72，其中 `LLM-in-the-Loop` 20 条、`traditional` 33 条、`Not-Sure` 19 条。

### TypeScript 清理

回收本次容器使用 `docker run --rm` 自动完成；宿主机 `.workspace` 中的源码、数据库和 SARIF 是需要保留的实验 artifact。确认不再需要时，只删除当前目标的精确目录，不删除共享的 CodeQL CLI/QL pack checkout：

```bash
rm -rf .workspace/project-sources/FlowiseAI__Flowise_CVE-2025-55346_2.2.6 \
       .workspace/codeql-dbs/FlowiseAI__Flowise_CVE-2025-55346_2.2.6 \
       .workspace/codeql-results/FlowiseAI__Flowise_CVE-2025-55346_2.2.6.sarif
```

## Step 2：创建实验容器并获取目标源码

### 通用步骤

使用 baseline 镜像创建一个具名实验容器。该容器从本步骤开始持续保留，后续依赖安装、Source Identification 和 Pysa 分析均在其中执行，完成全部分析并回收结果后再删除。TaintP2X 根目录挂载到容器的 `/taintp2x`，因此 `.workspace` 中的源码和结果同时保存在宿主机上。

```bash
mkdir -p .workspace/project-sources

if docker container inspect <CONTAINER_NAME> >/dev/null 2>&1; then
  echo "container already exists: <CONTAINER_NAME>" >&2
  exit 1
fi

docker create \
  --name <CONTAINER_NAME> \
  --platform linux/amd64 \
  --mount type=bind,src="$PWD",dst=/taintp2x \
  --workdir /taintp2x \
  taintp2x:baseline \
  sleep infinity

docker start <CONTAINER_NAME>

docker exec <CONTAINER_NAME> bash -lc '
    set -e
    test ! -e /taintp2x/.workspace/project-sources/<TARGET_NAME>
    git clone --branch <REF> --depth 1 <REPO_URL> \
      /taintp2x/.workspace/project-sources/<TARGET_NAME>
    cd /taintp2x/.workspace/project-sources/<TARGET_NAME>
    test "$(git rev-parse HEAD)" = "<EXPECTED_COMMIT>"
  '
```

`<CONTAINER_NAME>`、`<TARGET_NAME>`、`<REPO_URL>`、`<REF>` 和 `<EXPECTED_COMMIT>` 均来自复现配置。成功标准是容器保持运行、clone 命令返回成功，且 `git rev-parse HEAD` 等于配置中的固定 commit。

### 当前测试目标示例

当前配置文件为 `REPRODUCTION_CONFIG.json`，实际命令如下：

```bash
mkdir -p .workspace/project-sources

if docker container inspect taintp2x-vanna-v0-3-4 >/dev/null 2>&1; then
  echo "container already exists: taintp2x-vanna-v0-3-4" >&2
  exit 1
fi

docker create \
  --name taintp2x-vanna-v0-3-4 \
  --platform linux/amd64 \
  --mount type=bind,src="$PWD",dst=/taintp2x \
  --workdir /taintp2x \
  taintp2x:baseline \
  sleep infinity

docker start taintp2x-vanna-v0-3-4

docker exec taintp2x-vanna-v0-3-4 bash -lc '
    set -e
    test ! -e /taintp2x/.workspace/project-sources/vanna-ai__vanna__v0.3.4
    git clone --branch v0.3.4 --depth 1 \
      https://github.com/vanna-ai/vanna \
      /taintp2x/.workspace/project-sources/vanna-ai__vanna__v0.3.4
    cd /taintp2x/.workspace/project-sources/vanna-ai__vanna__v0.3.4
    test "$(git rev-parse HEAD)" = \
      "570968d23d4f6c3060fa6977e76691128c27b064"
  '
```

本次执行创建的实验容器名为 `taintp2x-vanna-v0-3-4`。目标源码版本为 `v0.3.4`，commit 为 `570968d23d4f6c3060fa6977e76691128c27b064`；源码 artifact 位于 `.workspace/project-sources/vanna-ai__vanna__v0.3.4`。

## Step 3：安装目标项目依赖

### 通用步骤

在 Step 2 创建的实验容器中执行 `REPRODUCTION_CONFIG.json` 中的 `install_command`：

```bash
mkdir -p .workspace/dependency-install

set -o pipefail
docker exec <CONTAINER_NAME> bash -lc '
    set -e
    target=/taintp2x/.workspace/project-sources/<TARGET_NAME>
    cd "$target"
    <INSTALL_COMMAND>
    python -c "import <TARGET_IMPORT>; print(\"target-import-ok\")"
  ' \
  2>&1 | tee .workspace/dependency-install/<TARGET_NAME>.log
```

`install_command` 在目标源码根目录执行。

成功标准是安装命令返回 0，目标包可以导入，并且安装日志保存在 `.workspace/dependency-install/<TARGET_NAME>.log`。安装后的依赖保留在具名实验容器中，后续分析直接使用该容器，不再重复安装。

### 当前测试目标示例

当前配置中的 `install_command` 为 `python -m pip install -e .`，目标包含 `pyproject.toml`，Python 包名为 `vanna`：

```bash
mkdir -p .workspace/dependency-install

set -o pipefail
docker exec taintp2x-vanna-v0-3-4 bash -lc '
    set -e
    target=/taintp2x/.workspace/project-sources/vanna-ai__vanna__v0.3.4
    cd "$target"
    python -m pip install -e .
    python -c "import vanna; print(\"target-import-ok\")"
  ' \
  2>&1 | tee .workspace/dependency-install/vanna-ai__vanna__v0.3.4.log
```

本次执行成功安装 `vanna==0.3.4` 及其基础依赖，并成功导入配置中的 `target_import`（`vanna`）。安装日志保存在 `.workspace/dependency-install/vanna-ai__vanna__v0.3.4.log`。`set -o pipefail` 确保容器内安装失败时，整个带 `tee` 的命令返回失败。

## Step 4：识别并确认 LLM Source

### 通用步骤

在目标源码目录执行 Source Identification 的三个阶段。第一阶段使用 Python AST 扫描候选的 LLM 客户端属性使用；第二阶段把候选方法源码发送给远程 OpenAI-compatible 模型确认；第三阶段把确认结果转换成项目专用的 Pysa Source 文件。

远程确认阶段通过环境变量提供模型配置：

```bash
export OPENAI_API_KEY="<DEEPSEEK_API_KEY>"
export OPENAI_BASE_URL="https://api.deepseek.com"
export OPENAI_MODEL="deepseek-v4-flash"
export OPENAI_EXTRA_BODY='{"thinking":{"type":"disabled"}}'
```

在同一个实验容器中运行：

```bash
docker exec \
  -e OPENAI_API_KEY \
  -e OPENAI_BASE_URL \
  -e OPENAI_MODEL \
  -e OPENAI_EXTRA_BODY \
  <CONTAINER_NAME> \
  bash -lc '
    set -e
    target=/taintp2x/.workspace/project-sources/<TARGET_NAME>
    python -c "from Source_Identification.analyze_assignments import run_analysis; run_analysis(\"$target\")"
    python -c "from Source_Identification.confirm_source import run_confirm_source; run_confirm_source(\"$target\")"
    python -c "from Source_Identification.make_pysa_source import extract_and_format_llm_paths; p=\"$target\"; n=\"<TARGET_NAME>\"; extract_and_format_llm_paths(f\"{p}/source/llm_analysis_{n}.json\", f\"{p}/source/self_llm_source_{n}.pysa\")"
  '
```

三个阶段分别生成 `source/analysis_source_<TARGET_NAME>.json`、`source/llm_analysis_<TARGET_NAME>.json` 和 `source/self_llm_source_<TARGET_NAME>.pysa`。模型适配代码位于 `Source_Identification/llm_client.py`；它读取上述环境变量并向 `<OPENAI_BASE_URL>/chat/completions` 发送请求。替换其他 OpenAI-compatible 服务时，只需调整运行时环境变量，或在该文件中调整通用请求适配。

### 当前测试目标示例

本次测试使用 DeepSeek 官方 API，配置为：

```bash
export OPENAI_API_KEY="<DEEPSEEK_API_KEY>"
export OPENAI_BASE_URL="https://api.deepseek.com"
export OPENAI_MODEL="deepseek-v4-flash"
export OPENAI_EXTRA_BODY='{"thinking":{"type":"disabled"}}'
```

实际运行命令为：

```bash
docker exec \
  -e OPENAI_API_KEY \
  -e OPENAI_BASE_URL \
  -e OPENAI_MODEL \
  -e OPENAI_EXTRA_BODY \
  taintp2x-vanna-v0-3-4 \
  bash -lc '
    set -e
    target=/taintp2x/.workspace/project-sources/vanna-ai__vanna__v0.3.4
    python -c "from Source_Identification.analyze_assignments import run_analysis; run_analysis(\"$target\")"
    python -c "from Source_Identification.confirm_source import run_confirm_source; run_confirm_source(\"$target\")"
    python -c "from Source_Identification.make_pysa_source import extract_and_format_llm_paths; p=\"$target\"; n=\"vanna-ai__vanna__v0.3.4\"; extract_and_format_llm_paths(f\"{p}/source/llm_analysis_{n}.json\", f\"{p}/source/self_llm_source_{n}.pysa\")"
  '
```

本次执行在 AST 阶段发现 5 个候选方法。远程确认结果中 2 个方法被判定为 LLM 调用，3 个 embedding 方法被判定为非 LLM 调用。输出文件为：

```text
.workspace/project-sources/vanna-ai__vanna__v0.3.4/source/analysis_source_vanna-ai__vanna__v0.3.4.json
.workspace/project-sources/vanna-ai__vanna__v0.3.4/source/llm_analysis_vanna-ai__vanna__v0.3.4.json
.workspace/project-sources/vanna-ai__vanna__v0.3.4/source/self_llm_source_vanna-ai__vanna__v0.3.4.pysa
```

最终 `.pysa` 文件包含两条 `TaintSource[LLMControlled]` 定义，分别对应 `OpenAI_Chat.submit_prompt` 和 `Anthropic_Chat.submit_prompt`。

可用下面的命令检查本次示例的远程确认没有写入请求错误，并且生成了两条 Source 定义：

```bash
python3 - <<'PY'
import json
from pathlib import Path

analysis = Path(".workspace/project-sources/vanna-ai__vanna__v0.3.4/source/llm_analysis_vanna-ai__vanna__v0.3.4.json")
source = Path(".workspace/project-sources/vanna-ai__vanna__v0.3.4/source/self_llm_source_vanna-ai__vanna__v0.3.4.pysa")
records = json.loads(analysis.read_text(encoding="utf-8"))
assert not any("error" in record for record in records)
assert sum(record.get("is_llm_call") is True for record in records) == 2
assert len([line for line in source.read_text(encoding="utf-8").splitlines() if line.strip()]) == 2
print("source-identification-output-ok")
PY
```

## Step 5：运行 Pysa 污点分析

### 通用步骤

在仍然运行的实验容器中执行 Pysa。源码目录、TaintP2X 内置模型和项目专属 Source 模型分别通过命令行传入；分析结果保存到 `.workspace/pysa-analysis/<TARGET_NAME>/results`。

```bash
mkdir -p .workspace/pysa-analysis/<TARGET_NAME>

docker exec <CONTAINER_NAME> bash -lc '
  set -e
  target=/taintp2x/.workspace/project-sources/<TARGET_NAME>
  artifact=/taintp2x/.workspace/pysa-analysis/<TARGET_NAME>
  cd /taintp2x
  pyre --noninteractive \
    --source-directory "$target" \
    --search-path /taintp2x/Taint_Propagation/stubs \
    --dot-pyre-directory "$artifact/.pyre" \
    analyze \
    --taint-models-path /taintp2x/Taint_Propagation/taint \
    --taint-models-path "$target/source" \
    --no-verify \
    --save-results-to "$artifact/results"
'
```

成功标准是命令返回 0，并生成 `taint-output.json` 和 `taint-metadata.json`。`taint-output.json` 是逐行 JSON 文件，需筛选其中 `kind` 为 `issue` 的记录；`taint-metadata.json` 记录模型校验信息和分析统计。

### 当前测试目标示例

本次在容器 `taintp2x-vanna-v0-3-4` 中运行，输出目录为 `.workspace/pysa-analysis/vanna-ai__vanna__v0.3.4/results`：

```bash
mkdir -p .workspace/pysa-analysis/vanna-ai__vanna__v0.3.4

docker exec taintp2x-vanna-v0-3-4 bash -lc '
  set -e
  target=/taintp2x/.workspace/project-sources/vanna-ai__vanna__v0.3.4
  artifact=/taintp2x/.workspace/pysa-analysis/vanna-ai__vanna__v0.3.4
  cd /taintp2x
  pyre --noninteractive \
    --source-directory "$target" \
    --search-path /taintp2x/Taint_Propagation/stubs \
    --dot-pyre-directory "$artifact/.pyre" \
    analyze \
    --taint-models-path /taintp2x/Taint_Propagation/taint \
    --taint-models-path "$target/source" \
    --no-verify \
    --save-results-to "$artifact/results"
'
```

本次分析完成于 Pyre/Pysa 0.9.23，返回码为 0，处理 1171 个模块并发现 2 条 issue。结果验证命令：

```bash
python3 - <<'PY'
import json
from pathlib import Path

result = Path(".workspace/pysa-analysis/vanna-ai__vanna__v0.3.4/results/taint-output.json")
issues = []
with result.open(encoding="utf-8") as handle:
    for line in handle:
        record = json.loads(line)
        if record.get("kind") == "issue":
            issues.append(record["data"])

assert len(issues) == 2
assert any(issue["code"] == 5001 and issue["line"] == 1279 for issue in issues)
for issue in issues:
    print(issue["code"], issue["filename"], issue["line"], issue["message"])
PY
```

实际结果为：

```text
5008 .workspace/project-sources/vanna-ai__vanna__v0.3.4/src/vanna/base/base.py 1258 Data from [LLMControlled] source(s) may reach [SQL] sink(s)
5001 .workspace/project-sources/vanna-ai__vanna__v0.3.4/src/vanna/base/base.py 1279 User specified data may reach a code execution sink
```

第二条结果对应 `VannaBase.ask` 中 `generate_plotly_code` 的返回值进入 `get_plotly_figure`，最终在 `base.py:1279` 的 `exec` 调用处命中 `RemoteCodeExecution`。其正向 Source 路径包含 `OpenAI_Chat.submit_prompt` 和 `Anthropic_Chat.submit_prompt`，与预期的 LLM 输出到代码执行利用链一致。分析元数据还记录了 21 个在当前目标环境中无法解析的模型校验提示；由于本次使用 `--no-verify`，这些提示不影响目标仓库的两条实际 issue 结果。

## Step 6：回收结果并清理实验容器

分析结果和日志已经通过 `/taintp2x/.workspace` bind mount 保存在宿主机。确认结果备份完成后执行：

```bash
docker rm -f <CONTAINER_NAME>
```

当前示例使用：

```bash
docker rm -f taintp2x-vanna-v0-3-4
```
