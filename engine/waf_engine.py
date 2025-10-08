from typing import List
from rules.inspection_rules import InspectionRule
from rules.http_requests import HttpRequest
import threading
import concurrent.futures
from functools import partial


class WAFEngine:
    def __init__(self, rules: List[InspectionRule], fail_safe : bool =False, workers:int = None):
        self.rules = rules
        self.fail_safe = fail_safe
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=workers)

    def check_rule(self, rule, request, stop_event=None):
        try:
            if stop_event and stop_event.is_set():
                return True, None  
                
            if not rule.check_request(request):
                if stop_event:
                    stop_event.set()
                return False, str(rule)
            return True, None
        except Exception as e:
            print(f"[Error] Exception in rule {rule}: {e}")
            if stop_event:
                stop_event.set()
            return False, f"Rule Error in {rule}"

    def inspect_request(self, request: HttpRequest):
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