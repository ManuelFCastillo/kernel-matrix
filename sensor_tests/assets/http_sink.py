"""
http_sink.py -- the far end of Falco's http_output and falcosidekick's webhook.

    http_sink.py PORT FILE

Appends one line per POST to FILE: {"path": ..., "body": <JSON or text>}.
Python 3.6 compatible, standard library only. Runs as a transient systemd
unit (systemd-run), so it outlives the ssh session that started it.
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Sink(BaseHTTPRequestHandler):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode("utf-8", "replace")
        try:
            body = json.loads(raw)
        except ValueError:
            body = raw
        with open(sys.argv[2], "a") as fh:
            fh.write(json.dumps({"path": self.path, "body": body}) + "\n")
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", int(sys.argv[1])), Sink).serve_forever()
