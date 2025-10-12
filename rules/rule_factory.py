from rules.sql_rules import SQLRule
from enum import Enum
import re

class RuleType(Enum):
    SQLi_RULE = 0
    XSS_RULE = 1
    NON_RULE = -1

class SQLRuleDictValidator():
    @staticmethod
    def validate(data: dict) -> None:
        """Validates that the provided dictionary contains all required keys for a SQLRule.

        Args:
            data (dict): The dictionary containing the rule's configuration.

        Raises:
            KeyError: If any required key is missing from the dictionary.
        """
        REQUIRED_KEYS = {"id", "name", "version", "logic", "metadata"}

        missing = REQUIRED_KEYS - data.keys()
        if missing:
            raise KeyError(f"Missing keys: {missing}")
        return True

class RuleFactory:
    @staticmethod
    def create_rule(rule :dict):
        """Creates an `InspectionRule` instance from a rule configuration dictionary.

        This method checks if the rule is enabled and then dispatches to the
        appropriate private creation method based on the rule's type.

        Args:
            rule (dict): A dictionary containing the configuration for a single rule.
                         Expected keys include 'enable', 'type', and type-specific details.

        Returns:
            Optional[InspectionRule]: An instance of `InspectionRule` if the rule is
                enabled and successfully created, otherwise `None`.
        """
        active_rule = rule.get("enable", False)
        if not active_rule:
            return

        rule_type = rule.get("type", -1)
        match RuleType(rule_type):
            case RuleType.SQLi_RULE:
                return RuleFactory.__create_sql_rule(rule)
            case RuleType.XSS_RULE:
                raise NotImplementedError
            case _:
                raise ValueError
            
    @staticmethod    
    def __create_sql_rule(rule:dict):
        """Creates a `SQLRule` instance from a validated configuration dictionary.

        This is a private helper method used by `create_rule` to specifically
        instantiate SQL injection detection rules. It validates the dictionary
        and extracts the necessary parameters.

        Args:
            rule (dict): The validated dictionary containing the SQL rule's configuration.

        Returns:
            SQLRule: A new instance of `SQLRule`.
        """
        if SQLRuleDictValidator.validate(rule):

            id = rule.get("id")
            name = rule.get("name")
            version = rule.get("version")
            pattern_logic = rule.get("logic")
            metadata = rule.get("metadata")
            pattern = re.compile(pattern_logic)
        
        return SQLRule(pattern, id, version, name)


    