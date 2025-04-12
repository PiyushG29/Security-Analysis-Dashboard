import sys
import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from http.server import BaseHTTPRequestHandler
import json
import asyncio
from starlette.responses import Response
from starlette.types import Receive, Send, Scope

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Import the FastAPI app
from asc_system.src.dashboard import app

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Forward the request to FastAPI app
        scope = {
            "type": "http",
            "method": "GET",
            "path": self.path,
            "headers": [(k.lower(), v.encode()) for k, v in self.headers.items()],
            "query_string": self.path.split('?')[1].encode() if '?' in self.path else b"",
            "client": (self.client_address[0], self.client_address[1]),
            "server": (self.server.server_address[0], self.server.server_address[1]),
        }
        
        async def receive():
            return {"type": "http.request", "body": b""}
            
        async def send(message):
            if message["type"] == "http.response.start":
                self.send_response(message["status"])
                for header, value in message["headers"]:
                    self.send_header(header.decode(), value.decode())
                self.end_headers()
            elif message["type"] == "http.response.body":
                self.wfile.write(message["body"])
        
        asyncio.run(app(scope, receive, send))

    def do_POST(self):
        # Forward the request to FastAPI app
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        scope = {
            "type": "http",
            "method": "POST",
            "path": self.path,
            "headers": [(k.lower(), v.encode()) for k, v in self.headers.items()],
            "query_string": self.path.split('?')[1].encode() if '?' in self.path else b"",
            "client": (self.client_address[0], self.client_address[1]),
            "server": (self.server.server_address[0], self.server.server_address[1]),
        }
        
        async def receive():
            return {"type": "http.request", "body": post_data}
            
        async def send(message):
            if message["type"] == "http.response.start":
                self.send_response(message["status"])
                for header, value in message["headers"]:
                    self.send_header(header.decode(), value.decode())
                self.end_headers()
            elif message["type"] == "http.response.body":
                self.wfile.write(message["body"])
        
        asyncio.run(app(scope, receive, send))

# Vercel requires this specific handler
handler = Handler 