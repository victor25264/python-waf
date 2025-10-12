from rules.sql_rules import SQLRule
from rules.rule_loader import InspectionRuleLoader
from engine.waf_engine import WAFEngine
from proxy.proxy import ProxyServer
from dotenv import load_dotenv
import os
import re
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


load_dotenv()

LISTEN_PORT = os.getenv("LISTEN_PORT")
BACKEND_URL = os.getenv("BACKEND_URL")
RULES = os.getenv("RULES")

def main():
    rules = open(RULES, "r")
    rule_loader = InspectionRuleLoader(rules)
    rules = rule_loader.load_rules()
    engine = WAFEngine(rules, False, 4)
    proxy = ProxyServer(waf_engine=engine, backend_url=BACKEND_URL, logger=logger)

    proxy.run(port=LISTEN_PORT)



if __name__ == "__main__":
    main()