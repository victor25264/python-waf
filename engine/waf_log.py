from dataclasses import dataclass


@dataclass
class WafLogEntry:
    """
    Represents a WAF log entry.
    """
    timestamp: float
    rule_id: str
    rule_name: str
    src_ip: str
    req_path: str
    req_method: str

    def get_all_data(self):
        return (self.timestamp, self.rule_id, self.rule_name, self.src_ip, self.req_path, self.req_method)

    @staticmethod
    def get_all_attr_insert():
        return ("(timestamp, rule_id, rule_name, src_ip, req_path, req_method)")
    
    @staticmethod
    def get_all_to_insert():
        return ("(?, ?, ?, ?, ?, ?)")