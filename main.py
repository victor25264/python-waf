from rules.sql_rules import SQLRule
from rules.rule_loader import InspectionRuleLoader
from engine.waf_engine import WAFEngine
from engine.waf_db import WAFDB
from proxy.proxy import ProxyServer
from dotenv import load_dotenv
import os
import re
import logging
import sqlite3


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


load_dotenv()

LISTEN_PORT = os.getenv("LISTEN_PORT")
BACKEND_URL = os.getenv("BACKEND_URL")
RULES = os.getenv("RULES")
DB_STATS= os.getenv("DB_STATS")
db_con = sqlite3.connect(DB_STATS, check_same_thread=False)

def main():
    rules = open(RULES, "r")
    rule_loader = InspectionRuleLoader(rules)
    rules = rule_loader.load_rules()

    waf_db = WAFDB(db_con)
    engine = WAFEngine(rules, False, 4, waf_db)
    proxy = ProxyServer(waf_engine=engine, backend_url=BACKEND_URL, logger=logger)

    proxy.run(port=LISTEN_PORT)



if __name__ == "__main__":
    main()