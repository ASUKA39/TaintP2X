# TaintP2X TypeScript 复现指南

本指南只描述当前 TypeScript/JavaScript CodeQL 迁移版本。所有实验 artifact 写入 `.workspace/`；命令均从 TaintP2X 根目录执行。需要 Docker（`linux/amd64`）、GitHub 网络和远程模型 API。目标源码、数据库、SARIF、Source 清单和验证结果均保留在 `.workspace/`，容器使用 `--rm` 回收。

## 测试目标

示例目标为 Flowise 2.2.6：

- 仓库：`https://github.com/FlowiseAI/Flowise`
- ref：`flowise@2.2.6`
- commit：`da04289ecf1c25dc4894737e9d00eac9f6d9ec7d`
- 条目：`CVE-2026-41265`

配置位于 `config.json`。通用目标只需替换 `target_name`、`repo_url`、`ref`、`expected_commit`、`source_dir` 和 artifact 路径；`install_command` 是目标依赖安装命令，`build_command` 可选。不要把目标仓库或依赖写入镜像。

## Step 1：构建迁移镜像

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

镜像提供 Node、TypeScript Compiler API 和脚本运行所需的 Python 依赖。示例验证输出包含 Node 20、TypeScript 5.4.5、Python 3.11 和 `python-runtime-ok`。

## Step 2：准备 CodeQL CLI 和官方 JavaScript/TypeScript pack

CodeQL 对 JavaScript 与 TypeScript 使用同一个 `javascript` extractor。CLI 和官方 QL 源码 checkout 放在 `.workspace`，可由多个实验复用：

```bash
mkdir -p .workspace/codeql
curl -L -o .workspace/codeql/codeql.zip \
  https://github.com/github/codeql-cli-binaries/releases/download/v2.23.2/codeql-linux64.zip
unzip -qo .workspace/codeql/codeql.zip -d .workspace/codeql
git clone --depth 1 --branch codeql-cli/v2.23.2 \
  https://github.com/github/codeql.git .workspace/codeql/repo
.workspace/codeql/codeql/codeql version
```

首次安装查询 pack 依赖：

```bash
.workspace/codeql/codeql/codeql pack install \
  --additional-packs .workspace/codeql/repo \
  --common-caches .workspace/codeql/cache \
  CodeQL_Queries
```

## Step 3：获取并固定目标源码

通用命令：

```bash
PROJECT_DIR=".workspace/project-sources/<TARGET_NAME>"
mkdir -p .workspace/project-sources
git clone --branch <REF> --depth 1 <REPO_URL> "$PROJECT_DIR"
test "$(git -C "$PROJECT_DIR" rev-parse HEAD)" = "<EXPECTED_COMMIT>"
```

示例：

```bash
TARGET_DIR=".workspace/project-sources/FlowiseAI__Flowise_CVE-2026-41265_2.2.6"
mkdir -p .workspace/project-sources
git clone --branch flowise@2.2.6 --depth 1 \
  https://github.com/FlowiseAI/Flowise "$TARGET_DIR"
test "$(git -C "$TARGET_DIR" rev-parse HEAD)" = \
  "da04289ecf1c25dc4894737e9d00eac9f6d9ec7d"
```

## Step 4：安装目标依赖

在目标源码根目录执行 `config.json` 的 `install_command`，需要构建时再执行 `build_command`：

```bash
docker run --rm --platform linux/amd64 --user "$(id -u):$(id -g)" \
  --mount type=bind,src="$PWD",dst=/taintp2x \
  --workdir /taintp2x/.workspace/project-sources/<TARGET_NAME> \
  taintp2x:typescript bash -lc '<INSTALL_COMMAND>'
```

示例 Flowise：

```bash
docker run --rm --platform linux/amd64 --user "$(id -u):$(id -g)" \
  --mount type=bind,src="$PWD",dst=/taintp2x \
  --workdir /taintp2x/.workspace/project-sources/FlowiseAI__Flowise_CVE-2026-41265_2.2.6 \
  taintp2x:typescript bash -lc 'pnpm install --frozen-lockfile'
```

## Step 5：运行完整检测和验证管线

先在宿主机设置模型 API key，然后运行一次完整管线：

```bash
export OPENAI_API_KEY='sk-281d0267e93b4955acf0847a0ebd73c0'
docker run --rm --platform linux/amd64 --user "$(id -u):$(id -g)" \
  --mount type=bind,src="$PWD",dst=/taintp2x \
  -e OPENAI_API_KEY \
  -e OPENAI_BASE_URL="https://api.deepseek.com" \
  -e OPENAI_MODEL="deepseek-v4-flash" \
  -e OPENAI_EXTRA_BODY='{"thinking":{"type":"disabled"}}' \
  --workdir /taintp2x taintp2x:typescript bash -lc \
  'python scripts/run_typescript_codeql.py --config config.json'
```

该命令依次执行 TypeScript AST Source 候选识别、模型确认、CodeQL Source 生成、数据库创建、28 条规则查询、SARIF 适配、`SourceDeterminer` 和 `FullyDeterminer`。它不依据旧 artifact 跳过阶段。CLI、官方 QL 仓库和缓存均使用 Step 2 在当前 TaintP2X `.workspace/codeql/` 中准备的内容，不依赖其他项目目录或宿主机全局 pack 缓存。规则由 `Taint_Propagation/taint/taint.config` 生成，查询使用 `path-problem` 和 `TaintP2XFlow::flowPath`。

## Step 6：检查结果与验证器

SARIF 位于 `.workspace/codeql-results/<TARGET>.sarif`；`codeFlows[].threadFlows[].locations` 是 source-to-sink 路径：

```bash
jq '{count:(.runs[0].results|length), paths:[.runs[0].results[] | {ruleId, codeFlows}]}' \
  .workspace/codeql-results/<TARGET>.sarif
```

脚本将 SARIF 转换为 `<SOURCE_DIR>/codeql-runs_<TARGET>/taint-output.json`，随后调用原版 `SourceDeterminer` 和 `FullyDeterminer`。两阶段均为静态审计，不运行目标代码；失败条目不写入伪造结论。验证日志位于 `.workspace/llm-validation/<TARGET>/`。

本次完整测试识别 61 个候选，对其中 23 个函数进行模型确认并确认 7 个 LLM 函数。28 条路径查询全部编译并运行，得到 2 条 `taintp2x/5001` finding；两条 SARIF `threadFlow` 均包含 11 个节点，转换后的 `codeql_path` 也各包含 11 个节点。修正 TypeScript 函数上下文提取后，`SourceDeterminer` 确认两条路径，`FullyDeterminer` 分别生成 `.workspace/llm-validation/FlowiseAI__Flowise_CVE-2026-41265_2.2.6/1/analysis_results.json` 和 `2/analysis_results.json`，均确认 LLM 生成的 Python 代码未经净化即进入 `pyodide.runPythonAsync`。

## Step 7：清理

容器因 `--rm` 自动回收。确认不再需要本次 artifact 后，只删除当前目标的精确目录：

```bash
rm -rf .workspace/project-sources/<TARGET_NAME> \
       .workspace/codeql-dbs/<TARGET_NAME> \
       .workspace/codeql-results/<TARGET_NAME>.sarif
```
