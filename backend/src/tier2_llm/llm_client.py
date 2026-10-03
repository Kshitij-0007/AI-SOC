"""Bounded local OpenAI-compatible LLM client."""
from __future__ import annotations
import requests

class LLMUnavailableError(RuntimeError): pass

class LocalLLMClient:
    def __init__(self, base_url: str, model_name: str, timeout_seconds: int = 30):
        self.base_url, self.model_name, self.timeout_seconds = base_url, model_name, timeout_seconds
    def generate(self, system_prompt: str, user_prompt: str, max_tokens: int = 512, temperature: float = 0.2) -> str:
        try:
            response = requests.post(self.base_url, json={"model": self.model_name, "messages": [{"role":"system", "content":system_prompt}, {"role":"user", "content":user_prompt}], "max_tokens":max_tokens, "temperature":temperature}, timeout=self.timeout_seconds)
            response.raise_for_status()
            return str(response.json()["choices"][0]["message"]["content"])
        except (requests.RequestException, KeyError, IndexError, TypeError) as exc:
            raise LLMUnavailableError("Local LLM is unavailable or returned an invalid response") from exc
