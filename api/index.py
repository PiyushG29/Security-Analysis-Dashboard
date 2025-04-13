import sys
import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from http.server import BaseHTTPRequestHandler
import json
import base64
import re
from datetime import datetime

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
                    @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap');
                    
                    :root {
                        --primary-color: #4CAF50;
                        --secondary-color: #45a049;
                        --background-color: #f5f5f5;
                        --text-color: #333;
                        --error-color: #f44336;
                        --success-color: #4CAF50;
                    }
                    
                    * {
                        margin: 0;
                        padding: 0;
                        box-sizing: border-box;
                    }
                    
                    body {
                        font-family: 'Poppins', sans-serif;
                        max-width: 1200px;
                        margin: 0 auto;
                        padding: 20px;
                        background-color: var(--background-color);
                        color: var(--text-color);
                    }
                    
                    .container {
                        background-color: white;
                        padding: 40px;
                        border-radius: 12px;
                        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                        animation: fadeIn 0.5s ease-in-out;
                    }
                    
                    @keyframes fadeIn {
                        from { opacity: 0; transform: translateY(20px); }
                        to { opacity: 1; transform: translateY(0); }
                    }
                    
                    h1 {
                        color: var(--text-color);
                        text-align: center;
                        margin-bottom: 40px;
                        font-size: 2.5em;
                        font-weight: 600;
                    }
                    
                    .upload-section {
                        display: flex;
                        flex-direction: column;
                        gap: 30px;
                        align-items: center;
                        margin-bottom: 40px;
                    }
                    
                    .file-input-container {
                        width: 100%;
                        max-width: 500px;
                        position: relative;
                    }
                    
                    .file-input {
                        width: 100%;
                        padding: 20px;
                        border: 2px dashed #ccc;
                        border-radius: 8px;
                        text-align: center;
                        cursor: pointer;
                        transition: all 0.3s ease;
                        background-color: #fafafa;
                    }
                    
                    .file-input:hover {
                        border-color: var(--primary-color);
                        background-color: #f0f0f0;
                    }
                    
                    .file-input.dragover {
                        border-color: var(--primary-color);
                        background-color: #e8f5e9;
                    }
                    
                    .submit-btn {
                        background-color: var(--primary-color);
                        color: white;
                        padding: 15px 30px;
                        border: none;
                        border-radius: 8px;
                        cursor: pointer;
                        font-size: 1.1em;
                        font-weight: 500;
                        transition: all 0.3s ease;
                        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    }
                    
                    .submit-btn:hover {
                        background-color: var(--secondary-color);
                        transform: translateY(-2px);
                        box-shadow: 0 4px 8px rgba(0,0,0,0.2);
                    }
                    
                    .submit-btn:active {
                        transform: translateY(0);
                    }
                    
                    .result-section {
                        margin-top: 30px;
                        animation: slideIn 0.5s ease-in-out;
                    }
                    
                    @keyframes slideIn {
                        from { opacity: 0; transform: translateX(-20px); }
                        to { opacity: 1; transform: translateX(0); }
                    }
                    
                    .analysis-card {
                        background-color: white;
                        border-radius: 8px;
                        padding: 20px;
                        margin-top: 20px;
                        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                        display: none;
                    }
                    
                    .analysis-card.show {
                        display: block;
                        animation: fadeIn 0.5s ease-in-out;
                    }
                    
                    .analysis-header {
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        margin-bottom: 15px;
                    }
                    
                    .analysis-title {
                        font-size: 1.2em;
                        font-weight: 600;
                    }
                    
                    .analysis-content {
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                        gap: 20px;
                    }
                    
                    .analysis-item {
                        background-color: #f8f9fa;
                        padding: 15px;
                        border-radius: 6px;
                    }
                    
                    .analysis-item-title {
                        font-weight: 500;
                        margin-bottom: 10px;
                        color: var(--primary-color);
                    }
                    
                    .loading {
                        display: none;
                        text-align: center;
                        margin: 20px 0;
                    }
                    
                    .loading-spinner {
                        width: 40px;
                        height: 40px;
                        border: 4px solid #f3f3f3;
                        border-top: 4px solid var(--primary-color);
                        border-radius: 50%;
                        animation: spin 1s linear infinite;
                        margin: 0 auto;
                    }
                    
                    @keyframes spin {
                        0% { transform: rotate(0deg); }
                        100% { transform: rotate(360deg); }
                    }
                    
                    .error-message {
                        background-color: #ffebee;
                        color: var(--error-color);
                        padding: 15px;
                        border-radius: 8px;
                        margin-top: 20px;
                        display: none;
                    }
                    
                    .success-message {
                        background-color: #e8f5e9;
                        color: var(--success-color);
                        padding: 15px;
                        border-radius: 8px;
                        margin-top: 20px;
                        display: none;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Security Analysis Dashboard</h1>
                    <div class="upload-section">
                        <div class="file-input-container">
                            <input type="file" name="file" class="file-input" id="fileInput" required>
                        </div>
                        <button type="button" class="submit-btn" id="uploadBtn">Upload & Analyze</button>
                    </div>
                    
                    <div class="loading" id="loading">
                        <div class="loading-spinner"></div>
                        <p>Analyzing file...</p>
                    </div>
                    
                    <div class="error-message" id="errorMessage"></div>
                    <div class="success-message" id="successMessage"></div>
                    
                    <div class="analysis-card" id="analysisCard">
                        <div class="analysis-header">
                            <h2 class="analysis-title">Analysis Results</h2>
                            <span class="analysis-timestamp" id="analysisTimestamp"></span>
                        </div>
                        <div class="analysis-content" id="analysisContent">
                            <!-- Analysis results will be populated here -->
                        </div>
                    </div>
                </div>
                
                <script>
                    const fileInput = document.getElementById('fileInput');
                    const uploadBtn = document.getElementById('uploadBtn');
                    const loading = document.getElementById('loading');
                    const errorMessage = document.getElementById('errorMessage');
                    const successMessage = document.getElementById('successMessage');
                    const analysisCard = document.getElementById('analysisCard');
                    const analysisContent = document.getElementById('analysisContent');
                    const analysisTimestamp = document.getElementById('analysisTimestamp');
                    
                    // Drag and drop functionality
                    fileInput.addEventListener('dragover', (e) => {
                        e.preventDefault();
                        fileInput.classList.add('dragover');
                    });
                    
                    fileInput.addEventListener('dragleave', () => {
                        fileInput.classList.remove('dragover');
                    });
                    
                    fileInput.addEventListener('drop', (e) => {
                        e.preventDefault();
                        fileInput.classList.remove('dragover');
                        fileInput.files = e.dataTransfer.files;
                    });
                    
                    uploadBtn.addEventListener('click', async () => {
                        const file = fileInput.files[0];
                        if (!file) {
                            showError('Please select a file first');
                            return;
                        }
                        
                        const formData = new FormData();
                        formData.append('file', file);
                        
                        try {
                            // Show loading state
                            loading.style.display = 'block';
                            errorMessage.style.display = 'none';
                            successMessage.style.display = 'none';
                            analysisCard.classList.remove('show');
                            
                            const response = await fetch('/upload', {
                                method: 'POST',
                                body: formData
                            });
                            
                            const data = await response.json();
                            
                            if (response.ok) {
                                showSuccess('File uploaded successfully!');
                                displayAnalysis(data);
                            } else {
                                showError(data.error || 'Upload failed');
                            }
                        } catch (error) {
                            showError('An error occurred during upload');
                        } finally {
                            loading.style.display = 'none';
                        }
                    });
                    
                    function showError(message) {
                        errorMessage.textContent = message;
                        errorMessage.style.display = 'block';
                        successMessage.style.display = 'none';
                    }
                    
                    function showSuccess(message) {
                        successMessage.textContent = message;
                        successMessage.style.display = 'block';
                        errorMessage.style.display = 'none';
                    }
                    
                    function displayAnalysis(data) {
                        // Update timestamp
                        analysisTimestamp.textContent = new Date().toLocaleString();
                        
                        // Clear previous analysis
                        analysisContent.innerHTML = '';
                        
                        // Add analysis items
                        if (data.analysis) {
                            Object.entries(data.analysis).forEach(([key, value]) => {
                                const item = document.createElement('div');
                                item.className = 'analysis-item';
                                item.innerHTML = `
                                    <div class="analysis-item-title">${formatKey(key)}</div>
                                    <div class="analysis-item-value">${formatValue(value)}</div>
                                `;
                                analysisContent.appendChild(item);
                            });
                        }
                        
                        // Show the analysis card
                        analysisCard.classList.add('show');
                    }
                    
                    function formatKey(key) {
                        return key.split('_').map(word => 
                            word.charAt(0).toUpperCase() + word.slice(1)
                        ).join(' ');
                    }
                    
                    function formatValue(value) {
                        if (typeof value === 'object') {
                            return JSON.stringify(value, null, 2);
                        }
                        return value;
                    }
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
                    
                    # Analyze the file content
                    analysis = self.analyze_file(file_content)
                    
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        "message": "File uploaded successfully",
                        "status": "success",
                        "file_size": len(file_content),
                        "analysis": analysis
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

    def analyze_file(self, content):
        """Analyze the file content and return analysis results"""
        try:
            # Convert bytes to string for analysis
            content_str = content.decode('utf-8', errors='ignore')
            
            analysis = {
                "file_size": len(content),
                "line_count": len(content_str.splitlines()),
                "word_count": len(content_str.split()),
                "character_count": len(content_str),
                "contains_ip": bool(re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content_str)),
                "contains_url": bool(re.search(r'https?://\S+', content_str)),
                "contains_email": bool(re.search(r'[\w\.-]+@[\w\.-]+\.\w+', content_str)),
                "timestamp": datetime.now().isoformat()
            }
            
            return analysis
        except Exception as e:
            return {"error": str(e)}

# Vercel requires this specific handler
handler = Handler 