from typing import List
from rules.inspection_rules import InspectionRule
from rules.http_requests import HttpRequest
import threading
import concurrent.futures
from functools import partial
from datetime import datetime
import threading

DB_QUERY = "INSERT INTO attacks_stats (time, rule_id, rule_name, src_ip, req_path, req_method) VALUES (?, ?, ?, ?, ?, ?)"

class WAFEngine:
    def __init__(self, rules: List[InspectionRule], fail_open : bool =True, workers:int = None, db_connnection = None):
        """
        Args:
            rules (List[InspectionRule]): A list of rule objects to be applied to requests.
            fail_open (bool, optional): Determines the WAF's behavior on a rule error.
                If True, the request is allowed (fails open).
                If False, the request is blocked (fails closed). Defaults to True.
            workers (int, optional): The number of worker threads for concurrent rule
                checking. Defaults to the ThreadPoolExecutor's default.
        """
        self.rules = rules
        self.fail_open = fail_open
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
        
        self.db_connnection = db_connnection
        self.db_cursor = db_connnection.cursor()
        self.db_lock = threading.Lock()

    def check_rule(self, rule, request, stop_event=None):
        """Worker function to check a single rule against a request.

        This method is designed to be executed in a separate thread. It checks the rule,
        handles exceptions, and respects a stop event for early termination.

        Args:
            rule (InspectionRule): The rule instance to execute.
            request (HttpRequest): The incoming request to inspect.
            stop_event (threading.Event, optional): An event that, when set, signals
                this function to terminate early. Defaults to None.
                documentation: https://docs.python.org/3/library/threading.html#threading.Event

        Returns:
            Tuple[bool, Optional[str]]: A tuple containing the result and a reason.
        """
        try:
            if stop_event and stop_event.is_set():
                return True, None  
                
            if not rule.check_request(request):

                if stop_event:
                    stop_event.set()

                if self.db_cursor:
                    with self.db_lock:
                        # save data if DB cursor is set
                        values = (datetime.now().timestamp(), rule.id, rule.name, request.src_ip, request.path, request.method)
                        self.db_cursor.execute(DB_QUERY, values)
                        self.db_connnection.commit()

                return False, str(rule)
            return True, None
        except Exception as e:
            print(f"[Error] Exception in rule {rule}: {e}")
            if stop_event:
                stop_event.set()
            return self.fail_open, f"Rule Error in {rule}"

    def inspect_request(self, request: HttpRequest):
        """Inspects an incoming request against all rules concurrently.

        This method submits all rules for a given request to a thread pool for parallel
        execution. As soon as any rule blocks the request, it signals all other running
        checks to stop and immediately returns the "blocked" decision.

        Args:
            request (HttpRequest): The request object to be inspected.

        Returns:
            Tuple[bool, Optional[str]]: The final inspection decision and error message is there is one.
        """
        if not self.executor:
            raise RuntimeError("Error initializing executor")
       
        stop_event = threading.Event()
        check_func = partial(self.check_rule, request=request, stop_event=stop_event)
        future_to_rule = {self.executor.submit(check_func, rule): rule for rule in self.rules}
        
        for future in concurrent.futures.as_completed(future_to_rule):
            result, error_msg = future.result()
            if not result:
                for f in future_to_rule:
                    if not f.done():
                        f.cancel()
                return False, error_msg
        
        return True, None

    def __del__(self):
        try:
            self.executor.shutdown()
        except Exception:
            pass