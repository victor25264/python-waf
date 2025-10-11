from rules.rule_loader import InspectionRuleLoader
import io
rules_str = r"""
{
    "rules": [
        {
            "id": "2caf8025-1ab7-4444-b152-ba904fb7eec6",
            "name": "Common SQL patterns",
            "version": 1,
            "type": 0,
            "logic": "",
            "enable": true,
            "metadata" : {
                "void" : "void"
            }
        },
        {
            "id": "2caf8025-1ab7-4444-b152-ba904fb7eec6",
            "name": "Common SQL patterns",
            "version": 1,
            "type": 0,
            "logic": "",
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
        
        rule_list = rule_loader.load_rules()

        assert type(rule_list) == list