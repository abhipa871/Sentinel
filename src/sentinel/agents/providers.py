"""Trusted provider endpoints; credentials live only in process memory/environment."""

import os


def build_model():
    provider = os.environ.get("SENTINEL_PROVIDER", "openai")
    if provider == "gemini":
        from langchain_google_genai import ChatGoogleGenerativeAI

        key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if not key:
            raise ValueError("Gemini mode requires GEMINI_API_KEY or GOOGLE_API_KEY")
        return ChatGoogleGenerativeAI(
            model=os.environ.get("SENTINEL_MODEL", "gemini-3.8-flash"),
            api_key=key,
            vertexai=False,
            temperature=0,
            timeout=90,
            max_retries=0,
            max_output_tokens=4096,
            thinking_level="low",
        )
    from langchain_openai import ChatOpenAI

    if provider == "openrouter":
        key = os.environ.get("OPENROUTER_API_KEY")
        if not key:
            raise ValueError("OpenRouter mode requires OPENROUTER_API_KEY")
        model = os.environ.get("SENTINEL_MODEL", "nvidia/nemotron-3-ultra-550b-a55b:free")
        return ChatOpenAI(
            model=model,
            api_key=key,
            base_url="https://openrouter.ai/api/v1",
            use_responses_api=False,
            temperature=0,
            timeout=min(float(os.environ.get("SENTINEL_MODEL_TIMEOUT", "90")), 120),
            max_retries=0,
            max_tokens=2048,
            extra_body={"reasoning": {"effort": "low"}},
        )
    if provider != "openai":
        raise ValueError("Unsupported model provider")
    if not os.environ.get("OPENAI_API_KEY"):
        raise ValueError("Deep Agents mode requires OPENAI_API_KEY")
    return ChatOpenAI(
        model=os.environ.get("SENTINEL_MODEL", "gpt-4.1-mini"), temperature=0, timeout=30, max_retries=1
    )
