from rules.rule_factory import RuleFactory
from rules.inspection_rules import InspectionRule
import json

class InspectionRuleLoader:
    def __init__(self,file_obj):
        """Initializes the InspectionRuleLoader with a file-like object.

        Args:
            file_obj: A file-like object (e.g., an open file) from which to read
                the rule configuration in JSON format.
        """
        self.file_obj = file_obj
    
    def load_rules(self):
        """Loads and instantiates WAF rules from the configured file-like object.

        This method reads the JSON content from the `file_obj`, parses it, and
        then uses a `RuleFactory` to create concrete `InspectionRule` instances
        based on the definitions found in the JSON.

        Returns:
            List[InspectionRule]: A list of instantiated `InspectionRule` objects
                that are ready to be used by the WAF engine.
        """
        rules_str = self.file_obj.read()
        rules_json = json.loads(rules_str)
        rules: list[InspectionRule] = []
        for rule in rules_json["rules"]:
            rule_created = RuleFactory.create_rule(rule)
            if rule_created:
                rules.append(rule_created)
        return rules
        