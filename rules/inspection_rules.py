from abc import ABC, abstractmethod
from rules.http_requests import HttpRequest

class InspectionRule(ABC):
    """
    Abstract class for rules that will inspect HttpRequests
    """
    def __init__(self, id:str):
        self.id = id

    @abstractmethod
    def check_request(self, request: HttpRequest):
        pass


class InspectionRuleException(Exception):
    pass