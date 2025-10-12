from engine.waf_log import WafLogEntry

class TestWafLogEntry():
    def test_number_dataLen_equal_attr(self):
        log_entry = WafLogEntry(
            timestamp=1678886400.500,
            rule_id="SQLI_942100",
            rule_name="SQL Injection Attack",
            src_ip="192.168.1.10",
            req_path="/search.php?id=1%27OR%271%27=%271",
            req_method="GET"
        )
        data_tuple = log_entry.get_all_data()
        attr_tuple = WafLogEntry.get_all_attr_insert()
        to_insert_tuple = WafLogEntry.get_all_to_insert()

        data_size = len(data_tuple)
        attr_size = attr_tuple.count(",") + 1
        to_insert_size =  to_insert_tuple.count(",") +1

        assert data_size == attr_size
        assert attr_size == to_insert_size
        