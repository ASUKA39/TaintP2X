import json
import sys
import os
from typing import Dict, List, Optional
import requests 
try:
    from .llm_client import LLMClient
except ImportError:  # Support running this file directly from its directory.
    from llm_client import LLMClient

# Provider, model, endpoint, and credentials are supplied through environment
# variables; see REPRODUCTION_GUIDE.md for the runtime configuration.
llm_client = LLMClient()

# 修改analyze_model_calls函数
def analyze_model_calls(method_code: str, language: str = "python") -> Dict:
    if language.lower() in {"typescript", "javascript", "ts", "js"}:
        prompt = """
        Determine whether the following TypeScript/JavaScript function calls an
        LLM and returns the model output. Return only JSON with the fields
        {{\"method_name\": <string>, \"is_llm_call\": <boolean>,
        \"reason\": <short explanation>}}.
        Candidate SDKs include OpenAI, Anthropic, LangChain, Google, Ollama,
        Groq, Mistral, Cohere, Vercel AI, and other model clients.

        Function:
        {method_code}
        """
    else:
        prompt = """
        请分析以下Python代码是否调用了大模型(如LLM、GPT等)并在返回值中返回了大模型的输出。
        请以JSON格式返回结果：
            {{
                "method_name": <方法名>,
                "is_llm_call": <布尔值，如果调用了大模型则为 true，否则为 false。>,
                "reason": <分析结果的原因，字符串类型。>,
            }}

        代码:
        {method_code}
    """
    
    return llm_client.analyze_code(prompt, method_code)

def extract_method_implementations(json_file_path: str, language: str = "python") -> List[Dict]:
    """
    Extracts method implementations (excluding __init__) from a JSON analysis file.

    Args:
        json_file_path (str): Path to the JSON analysis file.

    Returns:
        List[Dict]: A list of dictionaries, each containing method details and its code.
                    Returns an empty list if an error occurs or no methods are found.
    """
    if not os.path.exists(json_file_path):
        print(f"Error: JSON file not found at {json_file_path}")
        return []

    try:
        with open(json_file_path, 'r', encoding='utf-8') as f:
            analysis_data = json.load(f)
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from {json_file_path}")
        return []
    except Exception as e:
        print(f"Error reading file {json_file_path}: {e}")
        return []

    attribute_uses = analysis_data.get('attribute_uses', [])
    processed_methods = set()  # Set to store unique method identifiers (file, method_name, start_line, end_line)
    extracted_methods = []

    for item in attribute_uses:
        method_name = item.get('method')
        file_path = item.get('file')
        start_line = item.get('method_start_line')
        end_line = item.get('method_end_line')
        class_name = item.get('class')
        attribute_name = item.get('attribute')
        attribute_line = item.get('line')
        method_params = item.get('method_params') # <-- Add this line to get method_params

        # Skip __init__ methods
        if method_name == '__init__':
            continue

        method_identifier = item.get("function_id") or (
            file_path,
            method_name,
            start_line,
            end_line,
        )
        if method_identifier in processed_methods:
            continue
        processed_methods.add(method_identifier)

        # TypeScript frontend already provides the implementation text.  Keep
        # the same record shape consumed by the original confirmation loop.
        if language.lower() in {"typescript", "javascript", "ts", "js"}:
            method_code = item.get("method_code")
            if not method_code:
                print(f"Skipping TypeScript item without method_code: {item}")
                continue
            extracted_methods.append({
                "file_path": file_path,
                "class_name": class_name or "",
                "method_name": method_name,
                "start_line": start_line or item.get("line", 1),
                "end_line": end_line or item.get("line", 1),
                "attribute_name": attribute_name or item.get("attribute", ""),
                "attribute_line": attribute_line or item.get("line", 1),
                "method_code": method_code,
                "method_params": method_params,
                "module": item.get("module", ""),
                "function_id": item.get("function_id", ""),
                "sdk": item.get("sdk", {}),
            })
            continue

        # Ensure required fields are present
        if not all([method_name, file_path, start_line, end_line, class_name, attribute_name, attribute_line]):
            print(f"Skipping item due to missing data: {item}")
            continue

        try:
            with open(file_path, 'r', encoding='utf-8') as source_file:
                lines = source_file.readlines()
                if 1 <= start_line <= end_line <= len(lines):
                    method_code_lines = lines[start_line - 1:end_line]
                    method_code = "".join(method_code_lines)
                    extracted_methods.append({
                        "file_path": file_path,
                        "class_name": class_name,
                        "method_name": method_name,
                        "start_line": start_line,
                        "end_line": end_line,
                        "attribute_name": attribute_name,
                        "attribute_line": attribute_line,
                        "method_code": method_code,
                        "method_params": method_params # <-- Add this line to include method_params
                    })
                else:
                    print(f"Error: Invalid line range ({start_line}-{end_line}) for file {file_path} (total lines: {len(lines)})")
        except FileNotFoundError:
            print(f"Error: Source file not found at {file_path}")
        except Exception as e:
            print(f"Error reading source file {file_path}: {e}")

    return extracted_methods


def construct_full_method_path(project_name: str, method_info: Dict, language: str = "python") -> str:
    """
    Constructs the full method path from project name, file path, class name, and method name.
    e.g., langroid.language_models.openai_gpt.OpenAIGPT._generate

    Args:
        project_name: Name of the project (e.g., "langroid").
        method_info: Dictionary containing:
            - 'file_path': Absolute path to the Python file.
            - 'class_name': (Optional) Name of the class containing the method.
            - 'method_name': Name of the method.

    Returns:
        Full method path, e.g., "langroid.language_models.openai_gpt.OpenAIGPT._generate".
    """
    if language.lower() in {"typescript", "javascript", "ts", "js"}:
        module = method_info.get("module", "").replace("/", ".")
        class_name = method_info.get("class_name")
        method_name = method_info.get("method_name", "")
        if module:
            module = module.rsplit(".", 1)[0] if "." in module else module
            return ".".join(part for part in (module, class_name, method_name) if part)
        return ".".join(part for part in (class_name, method_name) if part)

    file_path = method_info['file_path']
    
    # Find the first occurrence of project_name in the path
    project_index = file_path.find(project_name)
    if project_index == -1:
        raise ValueError(f"Project name '{project_name}' not found in file path: {file_path}")
    
    # Extract the relevant part of the path (from project_name onwards, excluding project_name itself)
    # This assumes project_name is a directory in the path.
    # We add len(project_name) + len(os.sep) to skip the project_name directory and its separator.
    file_path_relative = file_path[project_index + len(project_name) + len(os.sep):]
    
    # Remove .py extension and replace path separators with dots
    file_path_parts = file_path_relative.replace('.py', '').replace(os.sep, '.')
    
    # Handle __init__.py case: remove the .__init__ part
    if file_path_parts.endswith('.__init__'):
        file_path_parts = file_path_parts[:-len('.__init__')]
    
    # Construct the full path, handling cases where class_name might be missing
    if method_info.get('class_name'):
        full_method_path = f"{file_path_parts}.{method_info['class_name']}.{method_info['method_name']}"
    else:
        full_method_path = f"{file_path_parts}.{method_info['method_name']}"
    
    return full_method_path


def run_confirm_source(project_root, language="python"):

    project_name = os.path.basename(project_root)

    json_file = f"{project_root}/source/analysis_source_{project_name}.json"
    output_json_file = f'{project_root}/source/llm_analysis_{project_name}.json'

    print(f"Analyzing attribute uses from {json_file}...")
    print("--------------------------------------------------")

    methods_to_analyze = extract_method_implementations(json_file, language)

    all_analysis_results = []

    for method_info in methods_to_analyze:
        print(f"File: {method_info['file_path']}")
        print(f"Class: {method_info['class_name']}")
        print(f"Method: {method_info['method_name']} (Lines {method_info['start_line']}-{method_info['end_line']})")
        print(f"Attribute '{method_info['attribute_name']}' used on line {method_info['attribute_line']}")
        if 'method_params' in method_info:
            print(f"Method Parameters: {method_info['method_params']}")
        print("--- Method Implementation ---")
        print(method_info['method_code'])

        analysis_response = analyze_model_calls(method_info['method_code'], language)
        print("--- LLM Call Analysis Raw Response ---")
        print(json.dumps(analysis_response, indent=4))

        extracted_analysis = None
        if analysis_response and 'choices' in analysis_response and analysis_response['choices']:
            message_content = analysis_response['choices'][0].get('message', {}).get('content')
            if message_content:
                try:
                    extracted_analysis = json.loads(message_content)
                    print("--- LLM Call Analysis Extracted JSON ---")
                    print(json.dumps(extracted_analysis, indent=4))
                    method_info.update(extracted_analysis)

                    if extracted_analysis.get('is_llm_call'):
                        full_method_path = construct_full_method_path(project_name, method_info, language)
                        method_info['full_method_path'] = full_method_path
                        print(f"Full LLM Method Path: {full_method_path}")

                    all_analysis_results.append(method_info)

                except json.JSONDecodeError:
                    print("Error: Could not decode nested JSON from LLM response content.")
                    all_analysis_results.append({"error": "JSON decode error in LLM content", **method_info})
            else:
                 print("Warning: 'content' field is missing or empty in LLM response message.")
                 all_analysis_results.append({"error": "Empty or missing content in LLM response", **method_info})
        else:
            print("Warning: Unexpected LLM response structure or empty choices.")
            all_analysis_results.append({"error": "Unexpected LLM response structure", **method_info})

        print("---------------------------")
        print("--------------------------------------------------")

    try:
        with open(output_json_file, 'w', encoding='utf-8') as outfile:
            json.dump(all_analysis_results, outfile, indent=4, ensure_ascii=False)
        print(f"Successfully saved all analysis results to {output_json_file}")
    except Exception as e:
        print(f"Error saving analysis results to file {output_json_file}: {e}")

if __name__ == "__main__":
    # Example usage for standalone execution
    project_name_example = 'langchain-0.0.327'
    
    run_confirm_source(project_name_example)
