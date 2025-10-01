import os
from dotenv import load_dotenv
from crewai import LLM

# Load environment variables
load_dotenv()

# Get Gemini API key from environment
GEMINI_API_KEY = os.getenv("GEMINI_KEY")

# Set environment variables for CrewAI to use Gemini
os.environ["GEMINI_API_KEY"] = GEMINI_API_KEY
os.environ["MODEL"] = "gemini/gemini-2.0-flash"


def get_gemini_llm(model: str = "gemini/gemini-2.0-flash", temperature: float = 0.1):
    """
    Create a Gemini LLM instance for CrewAI agents using the official CrewAI method.
    
    Args:
        model: Gemini model to use (should be in format "gemini/model-name")
        temperature: Temperature for response generation (0.0-1.0, lower = more deterministic)
        
    Returns:
        Configured LLM instance for CrewAI
    """
    try:
        # Create CrewAI LLM using the official method
        crew_llm = LLM(
            model=model,
            api_key=GEMINI_API_KEY,
            temperature=temperature
        )
        
        return crew_llm
        
    except Exception as e:
        raise RuntimeError(f"Failed to initialize Gemini LLM: {str(e)}")


def get_gemini_flash():
    """
    Get Gemini Flash model for fast, cost-effective analysis.
    
    Returns:
        Gemini Flash LLM instance
    """
    return get_gemini_llm(
        model="gemini/gemini-2.0-flash",
        temperature=0.1
    )


def get_gemini_pro():
    """
    Get Gemini Pro model for advanced analysis (more expensive).
    
    Returns:
        Gemini Pro LLM instance
    """
    return get_gemini_llm(
        model="gemini/gemini-2.5-pro-preview-06-05",  # Using Gemini Pro model
        temperature=0.1
    )




def get_gemini_with_specs(model: str, temperature: float = 0.1, max_tokens: int = 10000):
    """
    Get a Gemini LLM with specific configuration.
    
    Args:
        model: Model name (e.g., "gemini-2.0-flash", "gemini-2.5-pro-preview-06-05")
        temperature: Temperature for response generation (0.0-1.0)
        max_tokens: Maximum tokens for output
        
    Returns:
        Configured LLM instance
    """
    return get_gemini_llm(
        model=f"gemini/{model}",
        temperature=temperature
    )