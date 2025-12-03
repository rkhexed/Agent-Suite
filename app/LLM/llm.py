import os
from dotenv import load_dotenv
from crewai import LLM

# Load environment variables
load_dotenv()

# Get API keys from environment
GEMINI_API_KEY = os.getenv("GEMINI_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
MISTRAL_API_KEY = os.getenv("MISTRAL_KEY")

# Set environment variables for CrewAI to use Mistral by default
os.environ["MISTRAL_API_KEY"] = MISTRAL_API_KEY
os.environ["MODEL"] = "mistral/open-mistral-7b"  # Changed from mistral-small-latest to try different rate limits


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
        model="gemini/gemini-2.0-flash",
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

def get_groq_llm(model: str = "llama-3.3-70b-versatile", temperature: float = 0.1):
    """
    Create a Groq LLM instance for CrewAI agents.
    
    Args:
        model: Groq model ID
        temperature: Temperature for response generation (0.0-1.0, lower = more deterministic)
        
    Returns:
        Configured LLM instance for CrewAI
    """
    try:
        if not GROQ_API_KEY:
            raise ValueError("GROQ_API_KEY not found in environment variables")
            
        crew_llm = LLM(
            model=f"groq/{model}",
            api_key=GROQ_API_KEY,
            temperature=temperature
        )
        
        return crew_llm
        
    except Exception as e:
        raise RuntimeError(f"Failed to initialize Groq LLM: {str(e)}")


def get_groq_llama_70b():
    """
    
    Returns:
        Groq Llama 3.3 70B LLM instance
    """
    return get_groq_llm(
        model="llama-3.3-70b-versatile",
        temperature=0.1
    )


def get_groq_llama_8b():
    """
    Returns:
        Groq Llama 3.1 8B LLM instance
    """
    return get_groq_llm(
        model="llama-3.1-8b-instant",
        temperature=0.1
    )


def get_groq_mixtral():
    """
    
    Returns:
        Groq Mixtral LLM instance
    """
    return get_groq_llm(
        model="mixtral-8x7b-32768",
        temperature=0.1
    )


def get_mistral_llm(model: str = "mistral-small-latest", temperature: float = 0.1):
    """
    Create a Mistral LLM instance for CrewAI agents.
    
    Args:
        model: Mistral model to use (e.g., "mistral-large-latest", "mistral-medium-latest")
        temperature: Temperature for response generation (0.0-1.0, lower = more deterministic)
        
    Returns:
        Configured LLM instance for CrewAI
    """
    try:
        if not MISTRAL_API_KEY:
            raise ValueError("MISTRAL_API_KEY not found in environment variables")
            
        crew_llm = LLM(
            model=f"mistral/{model}",
            api_key=MISTRAL_API_KEY,
            temperature=temperature
        )
        
        return crew_llm
        
    except Exception as e:
        raise RuntimeError(f"Failed to initialize Mistral LLM: {str(e)}")


def get_mistral_small():
    """
    Get Mistral Small model for fast, efficient analysis.
    Recommended for free tier usage - 1B tokens available.
    
    Returns:
        Mistral Small LLM instance
    """
    return get_mistral_llm(
        model="mistral-small-latest",
        temperature=0.1
    )


def get_mistral_large():
    """
    Get Mistral Large model for high-quality analysis.
    Note: May be rate limited on free tier.
    
    Returns:
        Mistral Large LLM instance
    """
    return get_mistral_llm(
        model="mistral-large-latest",
        temperature=0.1
    )


def get_mistral_medium():
    """
    Get Mistral Medium model for balanced performance.
    
    Returns:
        Mistral Medium LLM instance
    """
    return get_mistral_llm(
        model="mistral-medium-latest",
        temperature=0.1
    )