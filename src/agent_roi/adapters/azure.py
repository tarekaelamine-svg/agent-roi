from __future__ import annotations

from .openai import OpenAIAgentsAdapter


class AzureAIFoundryAdapter(OpenAIAgentsAdapter):
    """Azure AI Foundry/OpenAI-compatible controlled-tool adapter."""
