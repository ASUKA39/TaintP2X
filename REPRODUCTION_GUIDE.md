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
