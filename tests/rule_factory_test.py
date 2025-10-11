from rules.sql_rules import SQLRule
from rules.rule_factory import RuleFactory


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
        assert rule_created.id == rule.get("id")
