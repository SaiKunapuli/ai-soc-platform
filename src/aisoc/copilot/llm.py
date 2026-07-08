"""Thin LLM client over Ollama's HTTP API (http://localhost:11434).

Free and local. Uses Ollama structured outputs (`format` = a JSON schema) so the
model is constrained to valid CopilotAnalysis JSON.
"""

from typing import Any

import httpx

from aisoc.config import settings


class LLMClient:
    def __init__(self, model: str | None = None, timeout: float = 120.0) -> None:
        self.model = model or settings.ollama_model
        self._http = httpx.Client(base_url=settings.ollama_url, timeout=timeout)

    def generate_json(self, system: str, prompt: str, schema: dict[str, Any]) -> dict[str, Any]:
        """One-shot generation constrained to the given JSON schema."""
        response = self._http.post(
            "/api/chat",
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
                "format": schema,
                "stream": False,
                "options": {"temperature": 0.1},
            },
        )
        response.raise_for_status()
        import json

        return json.loads(response.json()["message"]["content"])

    def generate_text(self, system: str, prompt: str) -> str:
        """Free-form generation (used for report prose)."""
        response = self._http.post(
            "/api/chat",
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
                "stream": False,
                "options": {"temperature": 0.3},
            },
        )
        response.raise_for_status()
        return response.json()["message"]["content"]
