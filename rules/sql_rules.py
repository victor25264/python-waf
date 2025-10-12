import re
from rules.inspection_rules import InspectionRule, InspectionRuleException
from rules.http_requests import HttpRequest


class SQLRule(InspectionRule):
    def __init__(self, pattern: re.Pattern, id: str, version: int, name:str):
        """
        Args:
            pattern (re.Pattern): A compiled regular expression pattern used to detect
                SQL injection signatures.
            id (str): A unique identifier for this SQL rule.
            version (int): The version of this specific SQL rule.
            name (str): A descriptive name for this SQL rule.
        """
        self.pattern = pattern
        super().__init__(id, version, name)

    def check_request(self, request: HttpRequest):
        """Inspects an incoming HTTP request for SQL injection patterns.

        It searches for the compiled regex pattern within the request's
        query parameters and (if present) its body.

        Args:
            request (HttpRequest): The HTTP request object to be inspected.

        Returns:
            bool: False if a SQL injection pattern is detected, True otherwise.
        """
        try:
            for value in request.query_params.values():
                if self.pattern.search(value):
                    return False
                
            if request.body and self.pattern.search(request.body):
                return False
        except Exception as e:
            raise InspectionRuleException(e)
        return True
    
    def __str__(self) -> str:
        return f"ID: {self.id}, NAME: {self.name}"