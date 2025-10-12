from engine.waf_db import WAFDB
from engine.waf_log import WafLogEntry

class MockCursor:
    def __init__(self):
        self.executed_calls = [] 

    def execute(self, query, values):
        """Records the query and values passed to execute."""
        self.executed_calls.append((query, values))

class MockConnection:
    def __init__(self):
        self.mock_cursor = MockCursor() 
        self.committed = False

    def cursor(self):
        """Returns the mock cursor for this connection."""
        return self.mock_cursor
    
    def commit(self):
        """Records that commit was called."""
        self.committed = True

class TestWAFBD:
    def test_waf_insert(self):
        log_entry = WafLogEntry(
            timestamp=1678886400.500,
            rule_id="SQLI_942100",
            rule_name="SQL Injection Attack",
            src_ip="192.168.1.10",
            req_path="/search.php?id=1%27OR%271%27=%271",
            req_method="GET"
        )
        mock_connection = MockConnection()

        waf_db = WAFDB(mock_connection)
        waf_db.insert_entry(log_entry)
        

        assert mock_connection.committed
        assert len(mock_connection.mock_cursor.executed_calls) == 1