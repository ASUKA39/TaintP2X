import json
import os
from typing import Dict

import requests

class LLMClient:
    """Small OpenAI-compatible client used by source confirmation.

    The provider is selected at runtime so the source-identification logic does
    not depend on a particular hosted model.  Credentials and endpoint details
    intentionally stay outside the repository.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
        extra_body: Dict | None = None,
    ):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY is required for LLM source confirmation")
        self.model = model or os.environ.get("OPENAI_MODEL", "deepseek-v4-flash")
        configured_base_url = base_url or os.environ.get(
            "OPENAI_BASE_URL", "https://api.deepseek.com"
        )
        configured_base_url = configured_base_url.rstrip("/")
        self.url = (
            configured_base_url
            if configured_base_url.endswith("/chat/completions")
            else f"{configured_base_url}/chat/completions"
        )

        if extra_body is not None:
            self.extra_body = extra_body
        else:
            raw_extra_body = os.environ.get("OPENAI_EXTRA_BODY", "")
            if raw_extra_body:
                try:
                    parsed_extra_body = json.loads(raw_extra_body)
                except json.JSONDecodeError as exc:
                    raise ValueError("OPENAI_EXTRA_BODY must contain valid JSON") from exc
                if not isinstance(parsed_extra_body, dict):
                    raise ValueError("OPENAI_EXTRA_BODY must contain a JSON object")
                self.extra_body = parsed_extra_body
            else:
                self.extra_body = {}
    
    def analyze_code(self, prompt: str, method_code: str) -> Dict:
        """
        分析代码片段是否调用了大模型
        
        Args:
            prompt: 提示词模板
            method_code: 要分析的代码片段
            
        Returns:
            大模型返回的JSON响应
        """
        full_prompt = prompt.format(method_code=method_code)
        return self.complete(full_prompt)

    def _request(self, messages, model=None, **kwargs) -> Dict:
        """Send the caller's messages and protocol options without rewriting them."""
        try:
            payload = {
                "model": model or self.model,
                "messages": messages,
            }
            payload.update({key: value for key, value in kwargs.items() if value is not None})
            payload.update(self.extra_body)

            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }

            response = requests.post(self.url, json=payload, headers=headers, timeout=120)
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            return {"error": f"Request Error: {e}", "analysis": None}
        except Exception as e:
            return {"error": f"Unexpected error: {e}", "analysis": None}

    def complete(self, prompt: str) -> Dict:
        """Send a single user prompt using the configured JSON response defaults."""
        return self._request(
            [{"role": "user", "content": prompt}],
            temperature=0,
            max_tokens=1024,
            response_format={"type": "json_object"},
        )

    def chat_completion(self, model=None, messages=None, **kwargs) -> Dict:
        """Compatibility API preserving message roles/order and protocol options."""
        return self._request(messages or [], model=model, **kwargs)
