import importlib
import sys
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from cipherloop.core.llm import get_cloud_llm, get_local_llm

CLOUD_ENV_VARS = (
    "CLOUD_PROVIDER",
    "OPENAI_API_KEY",
    "OPENAI_MODEL",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_MODEL",
    "XAI_API_KEY",
    "XAI_MODEL",
    "GEMINI_API_KEY",
    "GEMINI_MODEL",
)


def clear_cloud_environment(monkeypatch):
    for name in CLOUD_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def test_missing_local_llm_config(monkeypatch):
    monkeypatch.delenv("OLLAMA_BASE_URL", raising=False)
    monkeypatch.delenv("OLLAMA_MODEL", raising=False)

    with pytest.raises(ValueError, match="Startup Error: OLLAMA_BASE_URL and OLLAMA_MODEL"):
        get_local_llm()


def test_missing_cloud_provider_fails_clearly(monkeypatch):
    clear_cloud_environment(monkeypatch)

    with pytest.raises(ValueError, match="CLOUD_PROVIDER must be set"):
        get_cloud_llm()


def test_unknown_cloud_provider_fails_clearly(monkeypatch):
    clear_cloud_environment(monkeypatch)
    monkeypatch.setenv("CLOUD_PROVIDER", "unsupported")

    with pytest.raises(ValueError, match="Unknown CLOUD_PROVIDER 'unsupported'"):
        get_cloud_llm()


@pytest.mark.parametrize(
    ("provider", "key_name", "model_name"),
    [
        ("openai", "OPENAI_API_KEY", "OPENAI_MODEL"),
        ("anthropic", "ANTHROPIC_API_KEY", "ANTHROPIC_MODEL"),
        ("xai", "XAI_API_KEY", "XAI_MODEL"),
        ("gemini", "GEMINI_API_KEY", "GEMINI_MODEL"),
    ],
)
def test_selected_provider_validates_only_its_own_environment(monkeypatch, provider, key_name, model_name):
    clear_cloud_environment(monkeypatch)
    monkeypatch.setenv("CLOUD_PROVIDER", provider)

    with pytest.raises(ValueError, match=f"{key_name} and {model_name}"):
        get_cloud_llm()


@pytest.mark.parametrize(
    ("provider", "module_name", "class_name", "key_name", "model_name", "expected_kwargs"),
    [
        (
            "openai",
            "langchain_openai",
            "ChatOpenAI",
            "OPENAI_API_KEY",
            "OPENAI_MODEL",
            {"api_key": "test-key"},
        ),
        (
            "anthropic",
            "langchain_anthropic",
            "ChatAnthropic",
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_MODEL",
            {"api_key": "test-key"},
        ),
        (
            "xai",
            "langchain_xai",
            "ChatXAI",
            "XAI_API_KEY",
            "XAI_MODEL",
            {"xai_api_key": "test-key"},
        ),
        (
            "gemini",
            "langchain_google_genai",
            "ChatGoogleGenerativeAI",
            "GEMINI_API_KEY",
            "GEMINI_MODEL",
            {"api_key": "test-key"},
        ),
    ],
)
def test_cloud_factory_constructs_selected_chat_model(
    monkeypatch, provider, module_name, class_name, key_name, model_name, expected_kwargs
):
    clear_cloud_environment(monkeypatch)
    monkeypatch.setenv("CLOUD_PROVIDER", provider)
    monkeypatch.setenv(key_name, "test-key")
    monkeypatch.setenv(model_name, "test-model")
    constructor = Mock(return_value=object())

    with patch.dict(sys.modules, {module_name: SimpleNamespace(**{class_name: constructor})}):
        llm = get_cloud_llm(temperature=0.25)

    assert llm is not None
    constructor.assert_called_once_with(
        model="test-model", temperature=0.25, **expected_kwargs
    )


def test_importing_graph_does_not_require_cloud_credentials(monkeypatch):
    clear_cloud_environment(monkeypatch)
    sys.modules.pop("cipherloop.orchestrator.graph", None)
    sys.modules.pop("cipherloop.orchestrator.nodes", None)

    graph_module = importlib.import_module("cipherloop.orchestrator.graph")

    assert graph_module.build_graph is not None
