from app.Helper.helper_constant import GOOGLE_GENAI_API_KEY
from app.LLM.gemini import get_gemini_flash

def test_gemini():
    llm = get_gemini_flash()
    response = llm.invoke("Hello Gemini! Are you working?")
    print("Gemini API response:", response)

if __name__ == "__main__":
    test_gemini()