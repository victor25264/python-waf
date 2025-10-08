from dataclasses import dataclass, field

@dataclass
class HttpRequest():
    """
    Http representation of the request processed by the waf
    """
    path: str
    method: str = "GET"
    headers: dict = field(default_factory=dict)
    query_params: dict = field(default_factory=dict)
    body: str | None = None
