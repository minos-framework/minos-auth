import uuid
from threading import (
    Thread,
)

import requests
from flask import (
    Flask,
    jsonify,
)


class MockServer(Thread):
    def __init__(self, host="http://localhost", port=5000):
        super().__init__()
        self.host = host
        self.port = port
        self.app = Flask(__name__)
        self.url = "http://%s:%s" % (self.host, self.port)

        self.app.add_url_rule("/shutdown", view_func=self._shutdown_server)

    def _shutdown_server(self):
        from flask import (
            request,
        )

        if "werkzeug.server.shutdown" not in request.environ:
            raise RuntimeError("Not running the development server")
        request.environ["werkzeug.server.shutdown"]()
        return "Server shutting down..."

    def shutdown_server(self):
        requests.get("http://%s:%s/shutdown" % (self.host, self.port))
        self.join()

    def add_callback_response(self, url, callback, methods=("GET",)):
        # change name of method to mitigate flask exception
        callback.__name__ = str(uuid.uuid4())
        self.app.add_url_rule(url, view_func=callback, methods=methods)

    def add_json_response(self, url, serializable, methods=("GET",)):
        def callback(uuid: str):
            return jsonify(serializable)

        def callback2():
            return jsonify(serializable)

        if url == "/users/<uuid>":
            self.add_callback_response(url, callback, methods=methods)
        else:
            self.add_callback_response(url, callback2, methods=methods)

    def run(self):
        self.app.run(port=self.port)
