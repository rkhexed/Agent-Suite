from app.Helper.helper_constant import GOOGLE_GENAI_API_KEY
from langchain_google_genai import ChatGoogleGenerativeAI

def test_gemini():
    llm = ChatGoogleGenerativeAI(
        model="gemini-2.5-flash-preview-05-20",
        api_key=GOOGLE_GENAI_API_KEY,
        max_tokens=10000,
    )
    response = llm.invoke("Hello Gemini! Are you working?")
    print("Gemini API response:", response)

if __name__ == "__main__":
    test_gemini()