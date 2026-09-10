import json
import os
import re

def _ql_string(value):
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _render_codeql_sources(entries):
    clauses = []
    for entry in entries:
        if entry.get("is_llm_call") is not True:
            continue
        module = entry.get("module")
        method = entry.get("method_name")
        start_line = entry.get("start_line")
        end_line = entry.get("end_line")
        if not module or not method or not start_line or not end_line:
            continue
        clauses.append(
            "    (\n"
            f"      function.getFile().getRelativePath() = {_ql_string(module.lstrip('/'))} and\n"
            f"      function.getName() = {_ql_string(method)} and\n"
            f"      function.getLocation().getStartLine() = {start_line} and\n"
            f"      function.getLocation().getEndLine() = {end_line}\n"
            "    )"
        )
    body = "\n    or\n".join(clauses) if clauses else "    none()"
    return f'''/** Generated from confirmed Source Identification results. */
import javascript

module TaintP2XProjectSources {{
  predicate isConfirmedLLMFunction(Function function) {{
{body}
  }}

  predicate isConfirmedLLMCall(DataFlow::CallNode call) {{
    exists(Function function |
      isConfirmedLLMFunction(function) and
      call.getACallee() = function
    )
  }}
}}
'''


def extract_and_format_llm_paths(json_file_path, output_file_path, backend="pysa"):
    """
    从JSON文件中提取LLM函数的full_method_path和参数，并格式化写入文件。
    """
    llm_functions = []
    try:
        with open(json_file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"错误：文件未找到：{json_file_path}")
        return
    except json.JSONDecodeError:
        print(f"错误：无法解码JSON文件：{json_file_path}")
        return

    for entry in data:
        if entry.get('is_llm_call') == True:
            full_method_path = entry.get('full_method_path')
            # 直接从 entry 中获取 method_params
            params = entry.get('method_params')
            if full_method_path and params:
                # 格式化输出，使用提取到的参数
                formatted_line = f"def {full_method_path}( {params} ) -> TaintSource[LLMControlled]: ..."
                llm_functions.append(formatted_line)

    if backend.lower() == "codeql":
        os.makedirs(os.path.dirname(os.path.abspath(output_file_path)), exist_ok=True)
        with open(output_file_path, 'w', encoding='utf-8') as f:
            f.write(_render_codeql_sources(data))
        print(f"成功将LLM函数路径写入 CodeQL Source 模型：{output_file_path}")
    elif llm_functions:
        with open(output_file_path, 'w', encoding='utf-8') as f:
            for line in llm_functions:
                f.write(line + '\n')
        print(f"成功将LLM函数路径写入：{output_file_path}")
    else:
        print("未找到任何is_llm_call为true的LLM函数。")

if __name__ == "__main__":
    project_name = 'langchain-0.0.327'

    project_type = 'SSRF'

    json_file = f'/llm_web_serve/base_server/{project_type}/source/{project_name}/llm_analysis_{project_name}.json'
    output_file = f'/llm_web_serve/base_server/{project_type}/source/{project_name}/self_llm_source_{project_name}.pysa'

    extract_and_format_llm_paths(json_file, output_file)
