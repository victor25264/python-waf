from rules.sql_rules import SQLRule
from rules.rule_factory import RuleFactory, SQLRuleDictValidator
import pytest

class TestRuleFactory:
    def test_create_enable_sql(self):
        rule = {
            "id": "2caf8025-1ab7-4444-b152-ba904fb7eec6",
            "name": "Common SQL patterns",
            "version": 1,
            "type": 0,
            "logic": "",
            "enable": True,
            "metadata" : {

            }
        }
        rule_factory = RuleFactory()
        rule_created = rule_factory.create_rule(rule)
        assert type(rule_created) == SQLRule

    def test_create_enable_xss(self):
        rule = {
            "id": "2caf8025-1ab7-4444-b152-ba904fb7eec6",
            "name": "Common xss patterns",
            "version": 1,
            "type": 1,
            "logic": "",
            "enable": True,
            "metadata" : {

            }
        }
        rule_factory = RuleFactory()
        
        with pytest.raises(NotImplementedError):
            rule_created = rule_factory.create_rule(rule)

    def test_create_nonexitent_rule(self):
        rule = {
            "id": "2caf8025-1ab7-4444-b152-ba904fb7eec6",
            "name": "Common xss patterns",
            "version": 1,
            "type": -1,
            "logic": "",
            "enable": True,
            "metadata" : {

            }
        }
        rule_factory = RuleFactory()
        
        with pytest.raises(ValueError):
            rule_factory.create_rule(rule)

    def test_create_disable_rule(self):
        rule = {
            "id": "2caf8025-1ab7-4444-b152-ba904fb7eec6",
            "name": "Common xss patterns",
            "version": 1,
            "type": 0,
            "logic": "",
            "enable": False,
            "metadata" : {

            }
        }
        rule_factory = RuleFactory()
        
        rule_created = rule_factory.create_rule(rule)

        assert rule_created == None

    def test_sql_rule_validator_correct(self):
        rule = {
            "id": "2caf8025-1ab7-4444-b152-ba904fb7eec6",
            "name": "Common xss patterns",
            "version": 1,
            "type": 0,
            "logic": "",
            "enable": True,
            "metadata" : {

            }
        }
        
        valid = SQLRuleDictValidator.validate(rule)
        
        assert valid == True

    def test_sql_rule_validator_error(self):
        rule = {
            "name": "Common xss patterns",
            "version": 1,
            "type": 0,
            "logic": "",
            "enable": True,
            "metadata" : {

            }
        }
        
        with pytest.raises(KeyError)  as exc_info:
            SQLRuleDictValidator.validate(rule)
        
        assert exc_info.value.args[0] == r"Missing keys: {'id'}"