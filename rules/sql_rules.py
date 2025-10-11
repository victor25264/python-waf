import re
from rules.inspection_rules import InspectionRule, InspectionRuleException
from rules.http_requests import HttpRequest


class SQLRule(InspectionRule):
    def __init__(self, pattern: re.Pattern, id: str, version: int, name:str):
        self.pattern = pattern
        super().__init__(id, version, name)

    def check_request(self, request: HttpRequest):
        try:
            for value in request.query_params.values():
                if self.pattern.search(value):
                    return False
                
            if request.body and self.pattern.search(request.body):
                return False
        except Exception as e:
            raise InspectionRuleException(e)
        return True