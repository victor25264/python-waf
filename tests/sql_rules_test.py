from rules.http_requests import HttpRequest
from rules.sql_rules import SQLRule
from rules.inspection_rules import InspectionRuleException
import pytest
import re

sql_patterns = re.compile(r"""
            (\%27)|(\')|(\-\-)|(\%23)|(\#)|          # Comments and quotes
            (\b(ALTER|CREATE|DELETE|DROP|EXEC|INSERT|MERGE|SELECT|UPDATE|UNION)\b) # Keywords
        """, re.VERBOSE | re.IGNORECASE)
test_uuid="28cc5efe-e3c9-4cfa-8f3d-cd40d13d53d7"
test_name = "test_not_prod"
test_version = -1

class MockPattern:
    def search(self, str):
        raise Exception("Raised by mock pattern")

class TestSQLRules:
    def test_query_sqli_OR(self):
        request = HttpRequest(path="/query",
                              query_params={
                                  "user" : "' OR 1 == 1 --"
                              })

        SQLi_rule_query = SQLRule(sql_patterns, test_uuid, test_version, test_name)
        allowed = SQLi_rule_query.check_request(request)
        
        assert allowed == False

    def test_body_sqli_OR(self):
        request = HttpRequest(path="/query",
                              body="' OR 1 == 1 --")

        SQLi_rule_query = SQLRule(sql_patterns, test_uuid, test_version, test_name)
        allowed = SQLi_rule_query.check_request(request)
        
        assert allowed == False

    def test_query_benign(self):
        request = HttpRequest(path="/query",
                              query_params={
                                  "user" : "adam"
                              })
        

        SQLi_rule_query = SQLRule(sql_patterns, test_uuid, test_version, test_name)
        allowed = SQLi_rule_query.check_request(request)
        
        assert allowed == True

    def test_body_benign(self):
        request = HttpRequest(path="/query",
                              body="add comment")

        SQLi_rule_query = SQLRule(sql_patterns, test_uuid, test_version, test_name)
        allowed = SQLi_rule_query.check_request(request)
        
        assert allowed == True

    def test_srt_rule(self):
        name = "rule name"
        SQLi_rule_query = SQLRule(sql_patterns, test_uuid, test_version, name)
        
        expected_str = f"ID: {test_uuid}, NAME: {name}"
        str_sql_rule = str(SQLi_rule_query)
        
        assert str_sql_rule == expected_str

    # inspired from: https://stackoverflow.com/questions/23337471/how-do-i-properly-assert-that-an-exception-gets-raised-in-pytest
    def test_rule_raise_expection(self):
        SQLi_rule_query = SQLRule(MockPattern(), test_uuid, test_version, test_name)
        request = HttpRequest(path="/query",
                              body="add comment")

        with pytest.raises(InspectionRuleException):
            SQLi_rule_query.check_request(request)

    def test_mock_pattern_raise(self):
        mock = MockPattern()
        with pytest.raises(Exception) as exc_info:
            mock.search("str")
        
        assert exc_info.value.args[0] == "Raised by mock pattern"