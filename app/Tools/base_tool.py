from abc import ABC, abstractmethod
from typing import Dict, Any

class BaseTool(ABC):
    """Base class for all tools."""
    
    def __init__(self):
        self.name = self.__class__.name
        self.description = self.__class__.description

    @abstractmethod
    async def _run(self, *args: Any, **kwargs: Any) -> Any:
        """Execute the tool's main functionality."""
        pass

    async def run(self, *args: Any, **kwargs: Any) -> Any:
        """Run the tool with the given arguments."""
        return await self._run(*args, **kwargs)