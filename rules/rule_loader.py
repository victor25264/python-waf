from rules.rule_factory import RuleFactory
from rules.inspection_rules import InspectionRule
import json

class InspectionRuleLoader:
    def __init__(self,file_obj):
        self.file_obj = file_obj
    
    def load_rules(self):
        rules_str = self.file_obj.read()
        rules_json = json.loads(rules_str)
        rules: list[InspectionRule] = []
        for rule in rules_json["rules"]:
            rules.append(RuleFactory.create_rule(rule))
        return rules
        