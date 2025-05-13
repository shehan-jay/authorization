from abc import ABC, abstractmethod
from flask import request, jsonify
from functools import wraps
from typing import Any, Callable, TypeVar, Union, Tuple

F = TypeVar('F', bound=Callable[..., Any])

class BaseAuth(ABC):
    """Base class for authentication handlers."""
    
    def __init__(self) -> None:
        """Initialize base authentication handler."""
        self.port: int = 5000  # Default port

    @abstractmethod
    def authenticate(self, request: Any) -> bool:
        """Authenticate the request.
        
        Args:
            request: The request object to authenticate.
            
        Returns:
            bool: True if authentication is successful, False otherwise.
        """
        pass

    def requires_auth(self, f: F) -> F:
        """Decorator to require authentication for endpoints.
        
        Args:
            f: The function to decorate.
            
        Returns:
            F: The decorated function.
        """
        @wraps(f)
        def decorated(*args: Any, **kwargs: Any) -> Union[Tuple[dict, int], Any]:
            try:
                if not self.authenticate(request):
                    return jsonify({
                        'message': 'Authentication failed',
                        'status': 'error'
                    }), 401
                return f(*args, **kwargs)
            except Exception as e:
                return jsonify({
                    'message': f'Authentication error: {str(e)}',
                    'status': 'error'
                }), 401
        return decorated

    def get_port(self) -> int:
        """Get the port number for the server.
        
        Returns:
            int: The port number.
        """
        return self.port

    def set_port(self, port: int) -> None:
        """Set the port number for the server.
        
        Args:
            port: The port number to set.
        """
        self.port = port 