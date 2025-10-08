from rules.sql_rules import SQLRule
from engine.waf_engine import WAFEngine
from proxy.proxy import ProxyServer
from dotenv import load_dotenv
import os
import re


load_dotenv()

LISTEN_PORT = os.getenv("LISTEN_PORT")
BACKEND_URL = os.getenv("BACKEND_URL")

def main():
    sql_rules = []
    sql_patterns = [r"UNION", r"CREATE", r"\-\-"]
    dummy_id = 0
    for sql_pattern in sql_patterns:
        pattern = re.compile(sql_pattern)
        rule = SQLRule(pattern, str(dummy_id))
        sql_rules.append(rule)
        dummy_id += 1
    engine = WAFEngine(sql_rules, False, 4)
    proxy = ProxyServer(waf_engine=engine, backend_url=BACKEND_URL)

    proxy.run(port=LISTEN_PORT)

if __name__ == "__main__":
    main()