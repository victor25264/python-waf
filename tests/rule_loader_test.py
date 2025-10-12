from rules.rule_loader import InspectionRuleLoader
from rules.http_requests import HttpRequest
from rules.sql_rules import SQLRule
import io
rules_str = r"""
{
    "rules": [
        {
            "id": "2caf8025-1ab7-4444-b152-ba904fb7eec6",
            "name": "Common SQL patterns",
            "version": 1,
            "type": 0,
            "logic": "UPDATE",
            "enable": true,
            "metadata" : {
                "void" : "void"
            }
        },
        {
            "id": "2caf8025-1ab7-4444-b152-ba904fb7eec7",
            "name": "Common SQL patterns",
            "version": 1,
            "type": 0,
            "logic": "OR",
            "enable": true,
            "metadata" : {
                "void" : "void"
            }
        }
    ]
}
"""

class TestRuleLoaded:
    def test_load_json_rules(self):
        file_obj = io.StringIO(rules_str)
        rule_loader = InspectionRuleLoader(file_obj)
        request = HttpRequest(path="/query",
                              query_params={
                                  "user" : "' OR 1 == 1 --"
                              })
        
        rule_list = rule_loader.load_rules()
        rule_OR = rule_list[1]
        not_allowed = rule_OR.check_request(request)

        assert type(rule_list) == list
        assert type(rule_list[0]) == SQLRule
        assert not_allowed == False
        