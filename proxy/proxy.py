from engine.waf_engine import WAFEngine
from rules.http_requests import HttpRequest
from flask import Flask, request, Response
import requests
import logging

class ProxyServer:
    """A reverse proxy server that integrates with a Web Application Firewall (WAF) engine.

    Class inspired from: https://medium.com/customorchestrator/simple-reverse-proxy-server-using-flask-936087ce0afb
    """

    def __init__(self, waf_engine: WAFEngine, backend_url:str, logger: logging.Logger = None):
        """
        Args:
            waf_engine (WAFEngine): An instance of the WAFEngine (business layer) to delegate
                security inspections to. 
            backend_url (str): The base URL of the real backend application that
                this proxy protects.
            logger (logging.Logger, optional): A logger instance to record WAF decisions
                and proxy events. Defaults to None.
        """
        self.app = Flask(__name__)
        self.waf_engine = waf_engine
        self.backend_url = backend_url
        self.logger = logger
        self.app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])(self.proxy)
        self.app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])(self.proxy)

    def proxy(self, path):
        """Handles incoming HTTP requests, inspects them with the WAF, and forwards or blocks.

        This method is the core logic for the reverse proxy. It converts the Flask request
        into a generic HttpRequest model, passes it to the WAF, and acts based on the WAF's
        decision. Allowed requests are forwarded to the configured backend.

        Args:
            path (str): The requested path from the incoming HTTP request.

        Returns:
            Union[str, Response]: A Flask response object (or a string with status code)
        """

        simple_request = HttpRequest(
            path=f"/{path}",
            src_ip=request.remote_addr,
            method=request.method,
            headers=dict(request.headers),
            query_params=dict(request.args),
            body=request.get_data().decode('utf-8', errors='ignore')
        )

        is_allowed, reason = self.waf_engine.inspect_request(simple_request)

        if self.logger and reason:
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
        """Starts the Flask web server for the reverse proxy.

        Args:
            port (int): The port number on which the proxy server will listen for
                incoming client requests.
        """
        self.app.run(port=port, debug=True, host="0.0.0.0")