from langchain_google_genai import (
    ChatGoogleGenerativeAI,
    HarmBlockThreshold,
    HarmCategory,
)

from app.Helper.helper_constant import GOOGLE_GENAI_API_KEY

def get_gemini_safety_settings() -> dict:
    # Get the safety settings for the LLM model
    return{
        HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
        HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
        HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
        HarmCategory.HARM_CATEGORY_UNSPECIFIED: HarmBlockThreshold.BLOCK_NONE,
        HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE
    }

def get_gemini_flash(max_output_tokens = 10000) -> ChatGoogleGenerativeAI:
    return ChatGoogleGenerativeAI(
        model = "gemini-2.5-flash-preview-05-20",
        api_key = GOOGLE_GENAI_API_KEY,
        safety_settings = get_gemini_safety_settings(),
        max_tokens = max_output_tokens,
        max_retries = 2,
        # thinking_budget = 4096
    ) 

# Too expensive needs testing
def get_gemini_pro(max_output_tokens = 10000) -> ChatGoogleGenerativeAI:
    return ChatGoogleGenerativeAI(
        model = "gemini-2.5-pro-preview-06-05",
        api_key = GOOGLE_GENAI_API_KEY,
        safety_settings = get_gemini_safety_settings(),
        max_tokens = max_output_tokens,
        max_retries = 2,
        # thinking_budget = 4096
    ) 
