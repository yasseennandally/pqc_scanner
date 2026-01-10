import http.server
import socketserver

class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        b = self.rfile.read(n)
        print("---EVENT---")
        print(self.headers)
        print(b.decode("utf-8", "ignore"))
        self.send_response(200)
        self.end_headers()

socketserver.TCPServer(("", 9999), H).serve_forever()
