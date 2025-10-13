from engine.waf_db import WAFDB
from engine.waf_log import WafLogEntry


class MockCursor:
    def __init__(self):
        self.executed_calls = [] 
    
    def execute(self, query, values):
        """Records the query and values passed to execute."""
        self.executed_calls.append((query, values))

class MockCursorInsert(MockCursor):
    def __init__(self):
        super().__init__()

    def fetchall(self):
        return {}
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def close(self):
        pass

class MockCursorSelectNone(MockCursor):
    def __init__(self):
        super().__init__()
    
    def fetchall(self):
        return {}
    
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass
    def close(self):
        pass

class MockCursorSelect(MockCursor):
    def __init__(self):
        super().__init__()
    
    def fetchall(self):
        return [("a", "b", "c", "d", "e", "f")]
    
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def close(self):
        pass

class MockConnection:
    def __init__(self, mock_cursor: MockCursor):
        self.mock_cursor =mock_cursor 
        self.committed = False

    def cursor(self):
        """Returns the mock cursor for this connection."""
        return self.mock_cursor
    
    def commit(self):
        """Records that commit was called."""
        self.committed = True

class TestWAFBD:
    def test_wafdb_insert(self):
        log_entry = WafLogEntry(
            timestamp=1678886400.500,
            rule_id="SQLI_942100",
            rule_name="SQL Injection Attack",
            src_ip="192.168.1.10",
            req_path="/search.php?id=1%27OR%271%27=%271",
            req_method="GET"
        )
        mock_connection = MockConnection(MockCursorInsert())

        waf_db = WAFDB(mock_connection)
        waf_db.insert_entry(log_entry)
        

        assert mock_connection.committed
        assert len(mock_connection.mock_cursor.executed_calls) == 1


    def test_wafdb_get_by_time_none(self):
        mock_connection = MockConnection(MockCursorSelectNone())
        start = 100000.0
        end = 1000002.0
        desc = True

        waf_db = WAFDB(mock_connection)
        data = waf_db.get_by_time(start, end, desc)

        assert  len(mock_connection.mock_cursor.executed_calls) == 1
        assert type(data) == dict
        assert len(data.get("data")) == 0

    def test_wafdb_get_by_time(self):
        mock_connection = MockConnection(MockCursorSelect())
        start = 100000.0
        end = 1000002.0
        desc = True

        waf_db = WAFDB(mock_connection)
        data = waf_db.get_by_time(start, end, desc)

        assert  len(mock_connection.mock_cursor.executed_calls) == 1
        assert type(data) == dict
        assert len(data.get("data")) == 1
