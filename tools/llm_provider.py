"""
PHANTOM DFIR — LLM Provider Abstraction v1.0
Routes LLM calls to Ollama (default), Claude, OpenAI, or any compatible provider.

Usage:
  from tools.llm_provider import create_llm
  llm = create_llm(temperature=0.1)  # uses config.LLM_PROVIDER

Supports:
  - ollama   (default, free, local — needs Ollama running)
  - claude   (needs ANTHROPIC_API_KEY or --api-key)
  - openai   (needs OPENAI_API_KEY or --api-key)
  - groq     (needs GROQ_API_KEY or --api-key)
"""
import os
import config


def create_llm(temperature: float = 0.1, timeout: int = None):
    """Factory: create a LangChain-compatible LLM based on config.LLM_PROVIDER.

    Returns a LangChain BaseLLM/BaseChatModel instance.
    All providers use the same .invoke() interface via LangChain.
    """
    provider = getattr(config, "LLM_PROVIDER", "ollama").lower()
    model = config.OLLAMA_MODEL  # also used as model name for API providers
    api_key = getattr(config, "LLM_API_KEY", None)
    _timeout = timeout or config.TIMEOUT_LLM

    if provider == "ollama":
        return _create_ollama(model, _timeout, temperature)
    elif provider == "claude":
        return _create_claude(model, api_key, _timeout, temperature)
    elif provider == "openai":
        return _create_openai(model, api_key, _timeout, temperature)
    elif provider == "groq":
        return _create_groq(model, api_key, _timeout, temperature)
    else:
        print(f"[!] Unknown LLM provider '{provider}', falling back to Ollama")
        return _create_ollama(model, _timeout, temperature)


def _create_ollama(model, timeout, temperature):
    """Ollama — local, free, default."""
    from langchain_ollama import OllamaLLM
    return OllamaLLM(
        base_url=config.OLLAMA_BASE_URL,
        model=model,
        timeout=timeout,
        temperature=temperature,
    )


def _create_claude(model, api_key, timeout, temperature):
    """Anthropic Claude — requires ANTHROPIC_API_KEY."""
    try:
        from langchain_anthropic import ChatAnthropic
    except ImportError:
        print("[ERROR] langchain-anthropic not installed. Run: pip install langchain-anthropic")
        print("[*] Falling back to Ollama")
        return _create_ollama(config.OLLAMA_MODEL, timeout, temperature)

    key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        print("[ERROR] --provider claude requires ANTHROPIC_API_KEY env var or --api-key flag")
        print("[*] Falling back to Ollama")
        return _create_ollama(config.OLLAMA_MODEL, timeout, temperature)

    # Default to claude-sonnet if user passed an Ollama model name
    if "qwen" in model.lower() or "llama" in model.lower() or ":" in model:
        model = "claude-sonnet-4-20250514"
        print(f"[*] Auto-selecting Claude model: {model}")

    return ChatAnthropic(
        model=model,
        api_key=key,
        temperature=temperature,
        timeout=timeout,
        max_tokens=4096,
    )


def _create_openai(model, api_key, timeout, temperature):
    """OpenAI / compatible — requires OPENAI_API_KEY."""
    try:
        from langchain_openai import ChatOpenAI
    except ImportError:
        print("[ERROR] langchain-openai not installed. Run: pip install langchain-openai")
        print("[*] Falling back to Ollama")
        return _create_ollama(config.OLLAMA_MODEL, timeout, temperature)

    key = api_key or os.environ.get("OPENAI_API_KEY", "")
    if not key:
        print("[ERROR] --provider openai requires OPENAI_API_KEY env var or --api-key flag")
        print("[*] Falling back to Ollama")
        return _create_ollama(config.OLLAMA_MODEL, timeout, temperature)

    # Default to gpt-4o if user passed an Ollama model name
    if "qwen" in model.lower() or "llama" in model.lower() or ":" in model:
        model = "gpt-4o"
        print(f"[*] Auto-selecting OpenAI model: {model}")

    return ChatOpenAI(
        model=model,
        api_key=key,
        temperature=temperature,
        timeout=timeout,
        max_tokens=4096,
    )


def _create_groq(model, api_key, timeout, temperature):
    """Groq — fast cloud inference, requires GROQ_API_KEY."""
    try:
        from langchain_groq import ChatGroq
    except ImportError:
        print("[ERROR] langchain-groq not installed. Run: pip install langchain-groq")
        print("[*] Falling back to Ollama")
        return _create_ollama(config.OLLAMA_MODEL, timeout, temperature)

    key = api_key or os.environ.get("GROQ_API_KEY", "")
    if not key:
        print("[ERROR] --provider groq requires GROQ_API_KEY env var or --api-key flag")
        print("[*] Falling back to Ollama")
        return _create_ollama(config.OLLAMA_MODEL, timeout, temperature)

    if "qwen" in model.lower() or ":" in model:
        model = "llama-3.3-70b-versatile"
        print(f"[*] Auto-selecting Groq model: {model}")

    return ChatGroq(
        model=model,
        api_key=key,
        temperature=temperature,
        timeout=timeout,
        max_tokens=4096,
    )


def get_provider_info() -> dict:
    """Return current LLM provider configuration for reporting."""
    provider = getattr(config, "LLM_PROVIDER", "ollama").lower()
    return {
        "provider": provider,
        "model": config.OLLAMA_MODEL,
        "has_api_key": bool(getattr(config, "LLM_API_KEY", None)),
        "ollama_url": config.OLLAMA_BASE_URL if provider == "ollama" else None,
    }
