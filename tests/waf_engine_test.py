from rules.sql_rules import SQLRule
from rules.http_requests import HttpRequest
from engine.waf_engine import WAFEngine
from engine.waf_log import WafLogEntry
import threading
import pytest
import re

def create_multiple_sqlrules():
    sql_rules = []
    sql_patterns = [r"UNION", r"CREATE", r"\-\-", r"DROP",r"EXEC",r"INSERT",r"MERGE",r"SELECT",r"UPDATE",r"UNION"]
    dummy_id = 0
    for sql_pattern in sql_patterns:
        pattern = re.compile(sql_pattern)
        rule = SQLRule(pattern, str(dummy_id), -1, "test_not_prod")
        sql_rules.append(rule)
        dummy_id += 1
    return sql_rules

class MockWAFDB:
    def __init__(self):
        self.counter = 0
        self.values_list = []

    def insert_entry(self, values):
        self.counter += 1
        self.values_list.append(values)

class MockRule:
    def check_request(self,request):
        raise Exception("Raised from mock rule")

class TestWAFEngine:
    def test_engine_sqli_comment(self):
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

    def test_engine_parallel_sqli_comment(self):
        sql_rules = create_multiple_sqlrules()
        request = HttpRequest(path="/query",
                              query_params={
                                  "user" : "' OR 1 == 1 --"
                              })

        waf_engine = WAFEngine(sql_rules, workers=10)
        allowed, error = waf_engine.inspect_request(request)
        
        assert allowed == False

    def test_engine_parallel_bening(self):
        sql_rules = create_multiple_sqlrules()
        request = HttpRequest(path="/query",
                              query_params={
                                  "user" : "adam"
                              })

        waf_db_mock = MockWAFDB()
        waf_engine = WAFEngine(sql_rules, workers=10, waf_db=waf_db_mock)
        allowed, error = waf_engine.inspect_request(request)
        
        assert allowed == True
        assert waf_db_mock.counter == 0

    def test_engine_parallel_sqli_with_db(self):
        sql_rules = create_multiple_sqlrules()
        request = HttpRequest(path="/query",
                              query_params={
                                  "user" : "' OR 1 == 1 --"
                              })

        waf_db_mock = MockWAFDB()
        waf_engine = WAFEngine(sql_rules, workers=10, waf_db=waf_db_mock)
        allowed, error = waf_engine.inspect_request(request)
        
        assert allowed == False
        assert waf_db_mock.counter == 1
        assert type(waf_db_mock.values_list[0]) == WafLogEntry


    def test_engine_parallel_rule_exception(self):
        sql_rules = [MockRule()]
        request = HttpRequest(path="/query",
                              query_params={
                                  "user" : "' OR 1 == 1 --"
                              })
        
        waf_engine = WAFEngine(sql_rules, workers=10, )
        fail_open, error = waf_engine.inspect_request(request)
        assert fail_open 

    