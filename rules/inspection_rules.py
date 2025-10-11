from abc import ABC, abstractmethod
from rules.http_requests import HttpRequest
import json

class InspectionRule(ABC):
    """
    Abstract class for rules that will inspect HttpRequests
    """
    def __init__(self, id:str, version: int, name:str):
        self.id = id
        self.version = version
        self.name = name

    @abstractmethod
    def check_request(self, request: HttpRequest):
        pass


class InspectionRuleException(Exception):
    pass