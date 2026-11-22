from http.server import BaseHTTPRequestHandler, HTTPServer
BODY = open("./page.html","rb").read()
class H(BaseHTTPRequestHandler):
    def do_GET(s):
        if s.path != "/":
            s.send_response(404); s.send_header("Content-Length","0"); s.end_headers(); return
        s.send_response(200)
        s.send_header("Content-Type","text/html; charset=utf-8")
        s.send_header("Content-Length",str(len(BODY)))
        s.end_headers(); s.wfile.write(BODY)
    def log_message(s,*a): pass
HTTPServer(("127.0.0.1",9000),H).serve_forever()
