from dataclasses import dataclass, fields

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
        """
        Returns a tuple of attribute values suitable for SQL INSERT columns.
        """
        return (str(self.timestamp), self.rule_id, self.rule_name, self.src_ip, self.req_path, self.req_method)

    @classmethod
    def get_all_attr_insert(cls):
        """
        Returns a string of attribute names suitable for SQL INSERT columns,
        dynamically from dataclass fields.
        """
        field_names = [field.name for field in fields(cls)]
        return f"({', '.join(field_names)})"    
    
    @classmethod
    def get_all_to_insert(cls):
        """
        Returns a string of placeholders suitable for SQL INSERT values,
        dynamically based on the number of dataclass fields.
        """
        num_fields = len(fields(cls))
        placeholders = ", ".join(["?"] * num_fields)
        return f"({placeholders})"