from abc import ABC, abstractmethod
from rules.http_requests import HttpRequest
import json

class InspectionRule(ABC):
    def __init__(self, id:str, version: int, name:str):
        """Initializes an InspectionRule instance.

        Args:
            id (str): A unique identifier for the rule.
            version (int): The version number of the rule.
            name (str): A human-readable name for the rule.
        """
        self.id = id
        self.version = version
        self.name = name

    @abstractmethod
    def check_request(self, request: HttpRequest) -> bool:
        """Abstract method to inspect an incoming HTTP request.

        Concrete rule implementations must provide the logic to determine
        if the given request is allowed or should be blocked based on
        the rule's criteria.

        Args:
            request (HttpRequest): The HTTP request object to be inspected.

        Returns:
            bool: True if the request is allowed by this rule, False if it
                is detected as malicious and should be blocked.
        """
        pass


class InspectionRuleException(Exception):
    """Custom exception raised for errors encountered during rule processing.

    This exception allows for specific error handling when an issue occurs
    within the logic of an `InspectionRule`, providing more granular control
    over how the WAF responds to rule failures.
    """
    pass