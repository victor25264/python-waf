from rules.sql_rules import SQLRule
from rules.http_requests import HttpRequest
from engine.waf_engine import WAFEngine
import re

def create_multiple_sqlrules():
    sql_rules = []
    sql_patterns = [r"UNION", r"CREATE", r"\-\-"]
    dummy_id = 0
    for sql_pattern in sql_patterns:
        pattern = re.compile(sql_pattern)
        rule = SQLRule(pattern, str(dummy_id), -1, "test_not_prod")
        sql_rules.append(rule)
        dummy_id += 1
    return sql_rules

class TestWAFEngine:
    def test_engine_sqli_or(self):
        sql_rules = create_multiple_sqlrules()
        request = HttpRequest(path="/query",
                              query_params={
                                  "user" : "' OR 1 == 1 --"
                              })

        waf_engine = WAFEngine(sql_rules)
        allowed, error = waf_engine.inspect_request(request)
        
        assert allowed == False

    def test_engine_bening(self):
        sql_rules = create_multiple_sqlrules()
        request = HttpRequest(path="/query",
                              query_params={
                                  "user" : "adam"
                              })

        waf_engine = WAFEngine(sql_rules)
        allowed, error = waf_engine.inspect_request(request)
        
        assert allowed == True