import os
import pytest
from unittest.mock import patch
from cipherloop.core.llm import LLMSettings, get_cloud_llm, get_local_llm

def test_missing_local_llm_config():
    with patch.dict(os.environ, {"OLLAMA_BASE_URL": "", "OLLAMA_MODEL": ""}):
        LLMSettings.OLLAMA_BASE_URL = None
        LLMSettings.OLLAMA_MODEL = None
        with pytest.raises(ValueError, match="Startup Error: OLLAMA_BASE_URL and OLLAMA_MODEL"):
            get_local_llm()

def test_missing_anthropic_config():
    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "", "ANTHROPIC_MODEL": ""}):
        LLMSettings.CLOUD_PROVIDER = "anthropic"
        with pytest.raises(ValueError, match="Startup Error: ANTHROPIC_API_KEY and ANTHROPIC_MODEL"):
            get_cloud_llm()

def test_missing_openai_config():
    with patch.dict(os.environ, {"OPENAI_API_KEY": "", "OPENAI_MODEL": ""}):
        LLMSettings.CLOUD_PROVIDER = "openai"
        with pytest.raises(ValueError, match="Startup Error: OPENAI_API_KEY and OPENAI_MODEL"):
            get_cloud_llm()

def test_missing_xai_config():
    with patch.dict(os.environ, {"XAI_API_KEY": "", "XAI_MODEL": ""}):
        LLMSettings.CLOUD_PROVIDER = "xai"
        with pytest.raises(ValueError, match="Startup Error: XAI_API_KEY and XAI_MODEL"):
            get_cloud_llm()

def test_valid_cloud_config_factory():
    # Explicitly set the provider and keys without clearing the system OS environment
    with patch.dict(os.environ, {
        "CLOUD_PROVIDER": "openai",
        "OPENAI_API_KEY": "test-key",
        "OPENAI_MODEL": "gpt-4o"
    }):
        LLMSettings.CLOUD_PROVIDER = "openai"
        llm = get_cloud_llm()
        assert llm is not None
        assert llm.model_name == "gpt-4o"
