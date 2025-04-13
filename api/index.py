import sys
import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from http.server import BaseHTTPRequestHandler
import json
import base64

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Import the FastAPI app
from asc_system.src.dashboard import app

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            html_content = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Security Analysis Dashboard</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        max-width: 800px;
                        margin: 0 auto;
                        padding: 20px;
                        background-color: #f5f5f5;
                    }
                    .container {
                        background-color: white;
                        padding: 30px;
                        border-radius: 8px;
                        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    }
                    h1 {
                        color: #333;
                        text-align: center;
                        margin-bottom: 30px;
                    }
                    .upload-form {
                        display: flex;
                        flex-direction: column;
                        gap: 20px;
                        align-items: center;
                    }
                    .file-input {
                        padding: 10px;
                        border: 2px dashed #ccc;
                        border-radius: 4px;
                        width: 100%;
                        max-width: 400px;
                        text-align: center;
                        cursor: pointer;
                    }
                    .submit-btn {
                        background-color: #4CAF50;
                        color: white;
                        padding: 12px 24px;
                        border: none;
                        border-radius: 4px;
                        cursor: pointer;
                        font-size: 16px;
                        transition: background-color 0.3s;
                    }
                    .submit-btn:hover {
                        background-color: #45a049;
                    }
                    .result {
                        margin-top: 20px;
                        padding: 15px;
                        border-radius: 4px;
                        display: none;
                    }
                    .success {
                        background-color: #dff0d8;
                        color: #3c763d;
                        border: 1px solid #d6e9c6;
                    }
                    .error {
                        background-color: #f2dede;
                        color: #a94442;
                        border: 1px solid #ebccd1;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Security Analysis Dashboard</h1>
                    <form class="upload-form" action="/upload" method="post" enctype="multipart/form-data" id="uploadForm">
                        <input type="file" name="file" class="file-input" required>
                        <button type="submit" class="submit-btn">Upload File</button>
                    </form>
                    <div id="result" class="result"></div>
                </div>
                <script>
                    document.getElementById('uploadForm').addEventListener('submit', async (e) => {
                        e.preventDefault();
                        const formData = new FormData(e.target);
                        const resultDiv = document.getElementById('result');
                        
                        try {
                            const response = await fetch('/upload', {
                                method: 'POST',
                                body: formData
                            });
                            const data = await response.json();
                            
                            resultDiv.style.display = 'block';
                            if (response.ok) {
                                resultDiv.className = 'result success';
                                resultDiv.textContent = 'File uploaded successfully!';
                            } else {
                                resultDiv.className = 'result error';
                                resultDiv.textContent = data.error || 'Upload failed';
                            }
                        } catch (error) {
                            resultDiv.style.display = 'block';
                            resultDiv.className = 'result error';
                            resultDiv.textContent = 'An error occurred during upload';
                        }
                    });
                </script>
            </body>
            </html>
            """
            self.wfile.write(html_content.encode())

        except Exception as e:
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())

    def do_POST(self):
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            if self.path == '/upload':
                # Parse the multipart form data
                content_type = self.headers['Content-Type']
                boundary = content_type.split('boundary=')[1].encode()
                
                # Split the data into parts
                parts = post_data.split(boundary)
                
                # Find the file part
                file_data = None
                for part in parts:
                    if b'filename=' in part:
                        file_data = part
                        break
                
                if file_data:
                    # Extract the file content
                    file_content = file_data.split(b'\r\n\r\n')[1].split(b'\r\n--')[0]
                    
                    # Save the file (in a real implementation, you would process this file)
                    # For now, we'll just return a success message
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        "message": "File uploaded successfully",
                        "status": "success",
                        "file_size": len(file_content)
                    }).encode())
                else:
                    self.send_response(400)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        "error": "No file found in request"
                    }).encode())
            else:
                self.send_response(404)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({
                    "error": "Endpoint not found"
                }).encode())

        except Exception as e:
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())

# Vercel requires this specific handler
handler = Handler 