#!/usr/bin/env python3
"""
Simple test web server for PayBuddy toolkit testing
"""

from http.server import HTTPServer, SimpleHTTPRequestHandler
import json
import threading
import time

class TestHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'''
            <html>
            <head><title>PayBuddy Test Server</title></head>
            <body>
                <h1>PayBuddy Test API Server</h1>
                <p>This is a test server for cybersecurity toolkit testing.</p>
                <ul>
                    <li><a href="/api/status">API Status</a></li>
                    <li><a href="/admin">Admin Panel</a></li>
                    <li><a href="/config">Configuration</a></li>
                </ul>
            </body>
            </html>
            ''')
        elif self.path == '/api/status':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = {"status": "OK", "service": "PayBuddy Test API", "version": "1.0"}
            self.wfile.write(json.dumps(response).encode())
        elif self.path == '/admin':
            self.send_response(403)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<html><body><h1>403 Forbidden</h1><p>Access denied</p></body></html>')
        elif self.path == '/config':
            self.send_response(401)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<html><body><h1>401 Unauthorized</h1><p>Authentication required</p></body></html>')
        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<html><body><h1>404 Not Found</h1></body></html>')

def run_server():
    server = HTTPServer(('127.0.0.1', 8080), TestHandler)
    print("🌐 Test server running on http://127.0.0.1:8080")
    print("   Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Server stopped")
        server.server_close()

if __name__ == '__main__':
    run_server()