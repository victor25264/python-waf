from engine.waf_log import WafLogEntry
from datetime import datetime
from dataclasses import fields
from contextlib import closing


class WAFDB:
    def __init__(self, db_connection, table:str = "attacks_stats"):
        self.db_connection = db_connection
        self.table = table
    
    def insert_entry(self, logs_entry : WafLogEntry):
        with closing(self.db_connection.cursor()) as cursor: 
            columns_str = WafLogEntry.get_all_attr_insert()
            placeholders_str = WafLogEntry.get_all_to_insert()
            data_values = logs_entry.get_all_data()

            query = f"INSERT INTO {self.table} {columns_str} VALUES {placeholders_str}"
            cursor.execute(query, data_values)
        self.db_connection.commit()


    def get_by_time(self, start:float = None, end:float=datetime.now().timestamp(), desc:bool = True):
        results = []
        with closing(self.db_connection.cursor()) as cursor:
            select_columns_str = WafLogEntry.get_all_attr_insert().strip('()')
            
            query = f"SELECT {select_columns_str} FROM {self.table} WHERE timestamp >= ? AND timestamp <= ?"

            if start is None:
                return {"error": "start is needed"}
            if start >= end:
                return {"error": "start must be lower than end"}
            
            order_clause = "DESC" if desc else "ASC"
            query = f"{query} ORDER BY timestamp {order_clause}"
            
            cursor.execute(query, (start, end)) 
            
            log_data = {"data":{}}

            for row in cursor.fetchall():
                field_names = [field.name for field in fields(WafLogEntry)]
                log_data_dict = dict(zip(field_names, row))
                
                if 'timestamp' in log_data_dict and isinstance(log_data_dict['timestamp'], (int, float)):
                    log_data_dict['timestamp'] = datetime.fromtimestamp(log_data_dict['timestamp']).strftime("%d/%m/%Y, %H:%M:%S.%f")
                
                results.append(log_data_dict)
                
        
        return {"data":results}