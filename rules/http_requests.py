from dataclasses import dataclass, field

@dataclass
class HttpRequest():
    """
    Http representation of the request processed by the waf

    Simplified version of a request.
    """
    path: str
    method: str = "GET"
    src_ip: str = "GET"
    headers: dict = field(default_factory=dict)
    query_params: dict = field(default_factory=dict)
    body: str | None = None
