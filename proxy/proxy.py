from engine.waf_engine import WAFEngine
from rules.http_requests import HttpRequest
from flask import Flask, request, Response
import requests
import logging

class ProxyServer:
    def __init__(self, waf_engine: WAFEngine, backend_url:str, logger: logging.Logger = None):
        self.app = Flask(__name__)
        self.waf_engine = waf_engine
        self.backend_url = backend_url
        self.logger = logger
        self.app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])(self.proxy)
        self.app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])(self.proxy)

    def proxy(self, path):
        simple_request = HttpRequest(
            path=f"/{path}",
            method=request.method,
            headers=dict(request.headers),
            query_params=dict(request.args),
            body=request.get_data().decode('utf-8', errors='ignore')
        )

        is_allowed, reason = self.waf_engine.inspect_request(simple_request)

        if self.logger:
            self.logger.critical(f"Rule: {reason}")

        if not is_allowed:
            return "Forbidden: Your request was blocked.", 403

        try:
            backend_response = requests.request(
                method=request.method, url=f"{self.backend_url}/{path}",
                headers={k: v for (k, v) in request.headers if k != 'Host'},
                data=request.get_data(), params=request.args, allow_redirects=False
            )
            excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
            headers = [(n, v) for (n, v) in backend_response.raw.headers.items() if n.lower() not in excluded_headers]
            return Response(backend_response.content, backend_response.status_code, headers)
        except requests.exceptions.RequestException as e:
            return "Service Unavailable", 503

    def run(self, port):
        self.app.run(port=port, debug=True)