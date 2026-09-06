import os
from dotenv import load_dotenv
from langchain_core.language_models.chat_models import BaseChatModel

# Load environment variables at startup
load_dotenv()

class LLMSettings:
    CLOUD_PROVIDER = os.getenv("CLOUD_PROVIDER", "anthropic").lower()
    OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL")
    OLLAMA_MODEL = os.getenv("OLLAMA_MODEL")
    
    @classmethod
    def validate_local(cls):
        if not cls.OLLAMA_BASE_URL or not cls.OLLAMA_MODEL:
            raise ValueError("Startup Error: OLLAMA_BASE_URL and OLLAMA_MODEL must be set in .env")

    @classmethod
    def validate_cloud(cls):
        if cls.CLOUD_PROVIDER == "anthropic":
            if not os.getenv("ANTHROPIC_API_KEY") or not os.getenv("ANTHROPIC_MODEL"):
                raise ValueError("Startup Error: ANTHROPIC_API_KEY and ANTHROPIC_MODEL are required when CLOUD_PROVIDER=anthropic")
        elif cls.CLOUD_PROVIDER == "openai":
            if not os.getenv("OPENAI_API_KEY") or not os.getenv("OPENAI_MODEL"):
                raise ValueError("Startup Error: OPENAI_API_KEY and OPENAI_MODEL are required when CLOUD_PROVIDER=openai")
        elif cls.CLOUD_PROVIDER == "xai":
            if not os.getenv("XAI_API_KEY") or not os.getenv("XAI_MODEL"):
                raise ValueError("Startup Error: XAI_API_KEY and XAI_MODEL are required when CLOUD_PROVIDER=xai")
        else:
            raise ValueError(f"Startup Error: Unknown CLOUD_PROVIDER '{cls.CLOUD_PROVIDER}'. Must be anthropic, openai, or xai")

def get_cloud_llm(temperature: float = 0.1) -> BaseChatModel:
    LLMSettings.validate_cloud()
    
    if LLMSettings.CLOUD_PROVIDER == "anthropic":
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(
            model=os.getenv("ANTHROPIC_MODEL"),
            api_key=os.getenv("ANTHROPIC_API_KEY"),
            temperature=temperature
        )
        
    elif LLMSettings.CLOUD_PROVIDER == "openai":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=os.getenv("OPENAI_MODEL"),
            api_key=os.getenv("OPENAI_API_KEY"),
            temperature=temperature
        )
        
    elif LLMSettings.CLOUD_PROVIDER == "xai":
        from langchain_xai import ChatXAI
        return ChatXAI(
            model=os.getenv("XAI_MODEL"),
            xai_api_key=os.getenv("XAI_API_KEY"),
            temperature=temperature
        )

def get_local_llm(temperature: float = 0.1) -> BaseChatModel:
    LLMSettings.validate_local()
    from langchain_ollama import ChatOllama
    return ChatOllama(
        model=LLMSettings.OLLAMA_MODEL,
        base_url=LLMSettings.OLLAMA_BASE_URL,
        temperature=temperature
    )
