"""
models/llm_interface.py
=======================
Low-level interface to the local Ollama LLM server.

Ollama must be installed and running locally:
  https://ollama.com/download

Start Ollama and pull the default model once:
  ollama serve
  ollama pull deepseek-coder:6.7b
"""

import os
from typing import Iterator

import ollama
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Configuration (overridable via environment variables or .env file)
# ---------------------------------------------------------------------------
OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
DEFAULT_MODEL: str = os.getenv("LLM_MODEL", "deepseek-coder:6.7b")


class LLMInterface:
    """
    Thin wrapper around the Ollama Python client.

    Usage:
        llm = LLMInterface()
        response = llm.ask("Explain SQL injection")
        print(response)

    Streaming example:
        for chunk in llm.stream("Write a secure login function in Python"):
            print(chunk, end="", flush=True)
    """

    def __init__(self, model: str = DEFAULT_MODEL, base_url: str = OLLAMA_BASE_URL):
        self.model = model
        # Ollama client - points to the local Ollama server
        self.client = ollama.Client(host=base_url)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ask(self, prompt: str, system_prompt: str | None = None) -> str:
        """
        Send a prompt to the LLM and return the full response as a string.

        Parameters
        ----------
        prompt:        The user message / question.
        system_prompt: Optional system message that sets the model's behaviour.
        """
        messages = self._build_messages(prompt, system_prompt)
        response = self.client.chat(model=self.model, messages=messages)
        return response["message"]["content"]

    def stream(self, prompt: str, system_prompt: str | None = None) -> Iterator[str]:
        """
        Stream the LLM response token-by-token.

        Yields individual text chunks so the caller can print them in real time.
        """
        messages = self._build_messages(prompt, system_prompt)
        for chunk in self.client.chat(model=self.model, messages=messages, stream=True):
            yield chunk["message"]["content"]

    def is_available(self) -> bool:
        """
        Check whether the Ollama server is reachable and the model is loaded.
        """
        try:
            models = self.client.list()
            loaded = [m["name"] for m in models.get("models", [])]
            return any(self.model in name for name in loaded)
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_messages(
        prompt: str, system_prompt: str | None
    ) -> list[dict]:
        """Assemble the Ollama messages array."""
        messages: list[dict] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        return messages
