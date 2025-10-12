from engine.waf_log import WafLogEntry

class WAFDB:
    def __init__(self, db_coonection, table:str = "attacks_stats"):
        self.db_connection = db_coonection
        self.db_cursor = self.db_connection.cursor()
        self.table = table
    
    def insert_entry(self, logs_entry : WafLogEntry):
        query = f"INSERT INTO {self.table} {WafLogEntry.get_all_attr_insert()} VALUES  {WafLogEntry.get_all_to_insert()}"
        self.db_cursor.execute(query, logs_entry.get_all_data())
        self.db_connection.commit()