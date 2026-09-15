import os

from dotenv import load_dotenv
from langchain_core.language_models.chat_models import BaseChatModel

load_dotenv()


class LLMSettings:
    """Runtime configuration validation for CipherLoop's LLMs."""

    _CLOUD_PROVIDERS = ("openai", "anthropic", "xai", "gemini")

    @classmethod
    def cloud_provider(cls) -> str:
        provider = os.getenv("CLOUD_PROVIDER", "").strip().lower()
        if not provider:
            raise ValueError(
                "Startup Error: CLOUD_PROVIDER must be set to one of: "
                "openai, anthropic, xai, gemini"
            )
        if provider not in cls._CLOUD_PROVIDERS:
            raise ValueError(
                f"Startup Error: Unknown CLOUD_PROVIDER '{provider}'. Must be one of: "
                "openai, anthropic, xai, gemini"
            )
        return provider

    @classmethod
    def validate_local(cls) -> None:
        if not os.getenv("OLLAMA_BASE_URL") or not os.getenv("OLLAMA_MODEL"):
            raise ValueError("Startup Error: OLLAMA_BASE_URL and OLLAMA_MODEL must be set in .env")

    @classmethod
    def validate_cloud(cls) -> str:
        provider = cls.cloud_provider()
        key_name, model_name = {
            "openai": ("OPENAI_API_KEY", "OPENAI_MODEL"),
            "anthropic": ("ANTHROPIC_API_KEY", "ANTHROPIC_MODEL"),
            "xai": ("XAI_API_KEY", "XAI_MODEL"),
            "gemini": ("GEMINI_API_KEY", "GEMINI_MODEL"),
        }[provider]
        if not os.getenv(key_name) or not os.getenv(model_name):
            raise ValueError(
                f"Startup Error: {key_name} and {model_name} are required "
                f"when CLOUD_PROVIDER={provider}"
            )
        return provider


def get_cloud_llm(temperature: float = 0.1) -> BaseChatModel:
    """Build the selected cloud chat model without exposing SDK types elsewhere."""
    provider = LLMSettings.validate_cloud()

    if provider == "openai":
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            model=os.getenv("OPENAI_MODEL"),
            api_key=os.getenv("OPENAI_API_KEY"),
            temperature=temperature,
        )
    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic

        return ChatAnthropic(
            model=os.getenv("ANTHROPIC_MODEL"),
            api_key=os.getenv("ANTHROPIC_API_KEY"),
            temperature=temperature,
        )
    if provider == "xai":
        from langchain_xai import ChatXAI

        return ChatXAI(
            model=os.getenv("XAI_MODEL"),
            xai_api_key=os.getenv("XAI_API_KEY"),
            temperature=temperature,
        )

    from langchain_google_genai import ChatGoogleGenerativeAI

    return ChatGoogleGenerativeAI(
        model=os.getenv("GEMINI_MODEL"),
        api_key=os.getenv("GEMINI_API_KEY"),
        temperature=temperature,
    )


def get_local_llm(temperature: float = 0.1) -> BaseChatModel:
    LLMSettings.validate_local()
    from langchain_ollama import ChatOllama

    return ChatOllama(
        model=os.getenv("OLLAMA_MODEL"),
        base_url=os.getenv("OLLAMA_BASE_URL"),
        temperature=temperature,
    )
