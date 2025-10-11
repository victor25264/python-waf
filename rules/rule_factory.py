from rules.sql_rules import SQLRule
from enum import Enum
import re

class RuleType(Enum):
    SQLRULE = 0
    XSS_RULE = 1

class SQLRuleDictValidator():
    @staticmethod
    def validate(data: dict) -> None:
        REQUIRED_KEYS = {"id", "name", "version", "logic", "metadata"}

        missing = REQUIRED_KEYS - data.keys()
        if missing:
            raise KeyError(f"Missing keys: {missing}")

class RuleFactory:
    @staticmethod
    def create_rule(rule :dict):
        active_rule = rule.get("enable", False)
        if not active_rule:
            return

        rule_type = rule.get("type", -1)
        match RuleType(rule_type):
            case RuleType.SQLRULE:
                return RuleFactory.__create_sql_rule(rule)
            case RuleType.XSS_RULE:
                raise NotImplementedError
            case _:
                print(str(RuleType.SQLRULE.value))
                return
    @staticmethod    
    def __create_sql_rule(rule:dict):
        SQLRuleDictValidator.validate(rule)

        id = rule.get("id")
        name = rule.get("name")
        version = rule.get("version")
        pattern_logic = rule.get("logic")
        metadata = rule.get("metadata")
        pattern = re.compile(pattern_logic)
        
        return SQLRule(pattern, id, version, name)


    