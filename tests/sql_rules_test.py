from rules.http_requests import HttpRequest
from rules.sql_rules import SQLRule
import re

sql_patterns = re.compile(r"""
            (\%27)|(\')|(\-\-)|(\%23)|(\#)|          # Comments and quotes
            (\b(ALTER|CREATE|DELETE|DROP|EXEC|INSERT|MERGE|SELECT|UPDATE|UNION)\b) # Keywords
        """, re.VERBOSE | re.IGNORECASE)
test_uuid="28cc5efe-e3c9-4cfa-8f3d-cd40d13d53d7"

class TestSQLRules:
    def test_query_sqli_OR(self):
        request = HttpRequest(path="/query",
                              query_params={
                                  "user" : "' OR 1 == 1 --"
                              })

        SQLi_rule_query = SQLRule(sql_patterns, test_uuid, -1, "test_not_prod")
        allowed = SQLi_rule_query.check_request(request)
        
        assert allowed == False

    def test_body_sqli_OR(self):
        request = HttpRequest(path="/query",
                              body="' OR 1 == 1 --")

        SQLi_rule_query = SQLRule(sql_patterns, test_uuid, -1, "test_not_prod")
        allowed = SQLi_rule_query.check_request(request)
        
        assert allowed == False

    def test_query_benign(self):
        request = HttpRequest(path="/query",
                              query_params={
                                  "user" : "adam"
                              })
        

        SQLi_rule_query = SQLRule(sql_patterns, test_uuid, -1, "test_not_prod")
        allowed = SQLi_rule_query.check_request(request)
        
        assert allowed == True

    def test_body_benign(self):
        request = HttpRequest(path="/query",
                              body="add comment")

        SQLi_rule_query = SQLRule(sql_patterns, test_uuid, -1, "test_not_prod")
        allowed = SQLi_rule_query.check_request(request)
        
        assert allowed == True