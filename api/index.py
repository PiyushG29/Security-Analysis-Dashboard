import sys
import os
from fastapi import FastAPI, Request, UploadFile, File
from fastapi.responses import JSONResponse, HTMLResponse
from http.server import BaseHTTPRequestHandler
import json
import base64
import re
from datetime import datetime
import socket
from io import BytesIO
import dpkt

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Import the FastAPI app
from asc_system.src.dashboard import app

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            if self.path == '/':
                # Send HTML response
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                
                html_content = """
                <!DOCTYPE html>
                <html>
                <head>
                    <title>PCAP Analysis Tool</title>
                    <style>
                        body {
                            font-family: Arial, sans-serif;
                            max-width: 800px;
                            margin: 0 auto;
                            padding: 20px;
                            background-color: #f5f5f5;
                        }
                        .upload-container {
                            background-color: white;
                            padding: 20px;
                            border-radius: 8px;
                            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                            margin-bottom: 20px;
                        }
                        .file-input {
                            margin-bottom: 15px;
                        }
                        .upload-button {
                            background-color: #4CAF50;
                            color: white;
                            padding: 10px 20px;
                            border: none;
                            border-radius: 4px;
                            cursor: pointer;
                        }
                        .upload-button:hover {
                            background-color: #45a049;
                        }
                        .result {
                            margin-top: 20px;
                        }
                        .analysis-results {
                            background-color: white;
                            padding: 20px;
                            border-radius: 8px;
                            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                        }
                        .analysis-section {
                            margin-bottom: 20px;
                            padding-bottom: 20px;
                            border-bottom: 1px solid #eee;
                        }
                        .analysis-section:last-child {
                            border-bottom: none;
                        }
                        .protocol-stats {
                            display: grid;
                            grid-template-columns: repeat(2, 1fr);
                            gap: 10px;
                        }
                        .loading {
                            text-align: center;
                            padding: 20px;
                            color: #666;
                        }
                        .error {
                            color: #d32f2f;
                            padding: 10px;
                            background-color: #ffebee;
                            border-radius: 4px;
                        }
                        .ai-popup {
                            display: none;
                            position: fixed;
                            top: 50%;
                            left: 50%;
                            transform: translate(-50%, -50%);
                            background: white;
                            padding: 20px;
                            border-radius: 8px;
                            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                            z-index: 1000;
                            width: 80%;
                            max-width: 600px;
                        }
                        .ai-popup.active {
                            display: block;
                        }
                        .ai-popup-overlay {
                            display: none;
                            position: fixed;
                            top: 0;
                            left: 0;
                            right: 0;
                            bottom: 0;
                            background: rgba(0,0,0,0.5);
                            z-index: 999;
                        }
                        .ai-popup-overlay.active {
                            display: block;
                        }
                        .ai-chat-container {
                            max-height: 400px;
                            overflow-y: auto;
                            margin-bottom: 20px;
                        }
                        .ai-message {
                            margin: 10px 0;
                            padding: 10px;
                            border-radius: 4px;
                        }
                        .user-message {
                            background: #e3f2fd;
                            margin-left: 20%;
                        }
                        .ai-response {
                            background: #f5f5f5;
                            margin-right: 20%;
                        }
                        .close-popup {
                            position: absolute;
                            top: 10px;
                            right: 10px;
                            cursor: pointer;
                            font-size: 20px;
                        }
                        .ai-input-container {
                            display: flex;
                            gap: 10px;
                        }
                        .ai-input {
                            flex: 1;
                            padding: 8px;
                            border: 1px solid #ddd;
                            border-radius: 4px;
                        }
                        .ai-send {
                            padding: 8px 16px;
                            background: #4CAF50;
                            color: white;
                            border: none;
                            border-radius: 4px;
                            cursor: pointer;
                        }
                        .ai-send:hover {
                            background: #45a049;
                        }
                    </style>
                </head>
                <body>
                    <div class="upload-container">
                        <h1>PCAP Analysis Tool</h1>
                        <div class="file-input">
                            <input type="file" id="fileInput" accept=".pcap,.pcapng">
                        </div>
                        <button class="upload-button" id="uploadButton">Analyze PCAP</button>
                    </div>
                    <div id="result" class="result"></div>
                    
                    <!-- AI Popup -->
                    <div class="ai-popup-overlay"></div>
                    <div class="ai-popup">
                        <span class="close-popup">&times;</span>
                        <h2>Discuss with AI</h2>
                        <div class="ai-chat-container"></div>
                        <div class="ai-input-container">
                            <input type="text" class="ai-input" placeholder="Ask about the analysis...">
                            <button class="ai-send">Send</button>
                        </div>
                    </div>
                    
                    <script>
                        document.getElementById('uploadButton').addEventListener('click', async function() {
                            const fileInput = document.getElementById('fileInput');
                            const resultDiv = document.getElementById('result');
                            
                            if (!fileInput.files.length) {
                                resultDiv.innerHTML = '<div class="error">Please select a file first</div>';
                                return;
                            }
                            
                            const file = fileInput.files[0];
                            const formData = new FormData();
                            formData.append('file', file);
                            
                            try {
                                resultDiv.innerHTML = '<div class="loading">Analyzing file...</div>';
                                
                                const response = await fetch('/upload', {
                                    method: 'POST',
                                    body: formData
                                });
                                
                                if (!response.ok) {
                                    throw new Error(`HTTP error! status: ${response.status}`);
                                }
                                
                                const data = await response.json();
                                
                                if (data.error) {
                                    resultDiv.innerHTML = `<div class="error">Error: ${data.error}</div>`;
                                    return;
                                }
                                
                                // Format the analysis results
                                let html = '<div class="analysis-results">';
                                
                                // Basic file info
                                html += `
                                    <div class="analysis-section">
                                        <h3>File Information</h3>
                                        <p>File Size: ${(data.analysis.file_size / 1024).toFixed(2)} KB</p>
                                        <p>File Type: ${data.analysis.file_type || 'Unknown'}</p>
                                        <p>Analysis Time: ${new Date(data.analysis.timestamp).toLocaleString()}</p>
                                    </div>
                                `;
                                
                                // Protocol analysis
                                if (data.analysis.protocol_analysis) {
                                    html += `
                                        <div class="analysis-section">
                                            <h3>Protocol Analysis</h3>
                                            <p>Total Packets: ${data.analysis.total_packets || 0}</p>
                                            <div class="protocol-stats">
                                                <p>TCP: ${data.analysis.protocol_analysis.tcp || 0}</p>
                                                <p>UDP: ${data.analysis.protocol_analysis.udp || 0}</p>
                                                <p>ICMP: ${data.analysis.protocol_analysis.icmp || 0}</p>
                                                <p>Other: ${data.analysis.protocol_analysis.other || 0}</p>
                                            </div>
                                        </div>
                                    `;
                                }
                                
                                // IP analysis
                                if (data.analysis.top_source_ips && Object.keys(data.analysis.top_source_ips).length > 0) {
                                    html += `
                                        <div class="analysis-section">
                                            <h3>Top Source IPs</h3>
                                            <ul>
                                                ${Object.entries(data.analysis.top_source_ips).map(([ip, count]) => 
                                                    `<li>${ip}: ${count} packets</li>`
                                                ).join('')}
                                            </ul>
                                        </div>
                                    `;
                                }
                                
                                if (data.analysis.top_destination_ips && Object.keys(data.analysis.top_destination_ips).length > 0) {
                                    html += `
                                        <div class="analysis-section">
                                            <h3>Top Destination IPs</h3>
                                            <ul>
                                                ${Object.entries(data.analysis.top_destination_ips).map(([ip, count]) => 
                                                    `<li>${ip}: ${count} packets</li>`
                                                ).join('')}
                                            </ul>
                                        </div>
                                    `;
                                }
                                
                                // Additional analysis
                                html += `
                                    <div class="analysis-section">
                                        <h3>Additional Analysis</h3>
                                        <p>Contains IP Addresses: ${data.analysis.contains_ip ? 'Yes' : 'No'}</p>
                                        <p>Contains URLs: ${data.analysis.contains_url ? 'Yes' : 'No'}</p>
                                        <p>Contains Email Addresses: ${data.analysis.contains_email ? 'Yes' : 'No'}</p>
                                    </div>
                                `;
                                
                                html += '</div>';
                                resultDiv.innerHTML = html;
                                
                                // Add AI button to results
                                addAIButton();
                                
                            } catch (error) {
                                resultDiv.innerHTML = `<div class="error">Error uploading file: ${error.message}</div>`;
                            }
                        });
                        
                        // Add AI discussion functionality
                        const popup = document.querySelector('.ai-popup');
                        const overlay = document.querySelector('.ai-popup-overlay');
                        const closeBtn = document.querySelector('.close-popup');
                        const chatContainer = document.querySelector('.ai-chat-container');
                        const aiInput = document.querySelector('.ai-input');
                        const aiSend = document.querySelector('.ai-send');
                        
                        function togglePopup() {
                            popup.classList.toggle('active');
                            overlay.classList.toggle('active');
                        }
                        
                        closeBtn.addEventListener('click', togglePopup);
                        overlay.addEventListener('click', togglePopup);
                        
                        async function sendToGemini(message) {
                            try {
                                const response = await fetch('/api/analyze/chat', {
                                    method: 'POST',
                                    headers: {
                                        'Content-Type': 'application/json',
                                    },
                                    body: JSON.stringify({
                                        message: message
                                    })
                                });
                                
                                if (!response.ok) {
                                    throw new Error(`HTTP error! status: ${response.status}`);
                                }
                                
                                const data = await response.json();
                                return data.response;
                            } catch (error) {
                                console.error('Error:', error);
                                return 'Sorry, I encountered an error while processing your request. Please try again.';
                            }
                        }
                        
                        function addMessage(message, isUser = true) {
                            const messageDiv = document.createElement('div');
                            messageDiv.className = `ai-message ${isUser ? 'user-message' : 'ai-response'}`;
                            messageDiv.textContent = message;
                            chatContainer.appendChild(messageDiv);
                            chatContainer.scrollTop = chatContainer.scrollHeight;
                        }
                        
                        aiSend.addEventListener('click', async () => {
                            const message = aiInput.value.trim();
                            if (message) {
                                addMessage(message, true);
                                aiInput.value = '';
                                
                                const analysisData = document.querySelector('.analysis-results').innerText;
                                const prompt = `Based on this PCAP analysis: ${analysisData}\n\nUser question: ${message}`;
                                
                                const response = await sendToGemini(prompt);
                                addMessage(response, false);
                            }
                        });
                        
                        aiInput.addEventListener('keypress', (e) => {
                            if (e.key === 'Enter') {
                                aiSend.click();
                            }
                        });
                        
                        // Add AI button to results
                        function addAIButton() {
                            const resultDiv = document.getElementById('result');
                            const aiButton = document.createElement('button');
                            aiButton.className = 'upload-button';
                            aiButton.textContent = 'Discuss with AI';
                            aiButton.style.marginTop = '20px';
                            aiButton.addEventListener('click', togglePopup);
                            resultDiv.appendChild(aiButton);
                        }
                        
                    </script>
                </body>
                </html>
                """
                self.wfile.write(html_content.encode())
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b'Not Found')
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(str(e).encode())

    def do_POST(self):
        try:
            if self.path == '/upload':
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                
                # Parse multipart form data
                content_type = self.headers['Content-Type']
                boundary = content_type.split('boundary=')[1].encode()
                parts = post_data.split(boundary)
                
                # Find file data
                file_data = None
                for part in parts:
                    if b'filename=' in part:
                        file_data = part
                        break
                
                if file_data:
                    # Extract file content
                    file_content = file_data.split(b'\r\n\r\n')[1].split(b'\r\n--')[0]
                    
                    # Create BytesIO object for analysis
                    file_obj = BytesIO(file_content)
                    
                    # Analyze file
                    analysis_result = analyze_file(file_obj)
                    
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        "message": "File uploaded successfully",
                        "status": "success",
                        "analysis": analysis_result
                    }).encode())
                else:
                    self.send_response(400)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        "error": "No file found in request"
                    }).encode())
            else:
                # Forward other POST requests to FastAPI
                scope = {
                    "type": "http",
                    "method": "POST",
                    "path": self.path,
                    "headers": [(k.lower().encode(), v.encode()) for k, v in self.headers.items()],
                    "query_string": b"",
                }
                
                # Create a response object to capture FastAPI's response
                response = {"status": None, "headers": None, "body": b""}
                
                async def receive():
                    return {"type": "http.request", "body": post_data}
                
                async def send(message):
                    if message["type"] == "http.response.start":
                        response["status"] = message["status"]
                        response["headers"] = message["headers"]
                    elif message["type"] == "http.response.body":
                        response["body"] += message.get("body", b"")
                
                # Run the FastAPI application
                import asyncio
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(app(scope, receive, send))
                loop.close()
                
                # Send the response back
                self.send_response(response["status"] or 500)
                if response["headers"]:
                    for name, value in response["headers"]:
                        self.send_header(name.decode(), value.decode())
                self.end_headers()
                self.wfile.write(response["body"])
                
        except Exception as e:
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())

def analyze_file(file_obj):
    """Analyze the file content and return analysis results"""
    try:
        # Read file content
        content = file_obj.read()
        content_str = content.decode('utf-8', errors='ignore')
        
        # Basic file analysis
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
        
        # Try to analyze as PCAP file
        try:
            file_obj.seek(0)  # Reset file pointer
            pcap = dpkt.pcap.Reader(file_obj)
            
            # Initialize counters
            protocol_stats = {'tcp': 0, 'udp': 0, 'icmp': 0, 'other': 0}
            source_ips = {}
            dest_ips = {}
            
            # Analyze packets
            for timestamp, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if isinstance(eth.data, dpkt.ip.IP):
                        ip = eth.data
                        
                        # Count IPs
                        src_ip = socket.inet_ntoa(ip.src)
                        dst_ip = socket.inet_ntoa(ip.dst)
                        source_ips[src_ip] = source_ips.get(src_ip, 0) + 1
                        dest_ips[dst_ip] = dest_ips.get(dst_ip, 0) + 1
                        
                        # Count protocols
                        if isinstance(ip.data, dpkt.tcp.TCP):
                            protocol_stats['tcp'] += 1
                        elif isinstance(ip.data, dpkt.udp.UDP):
                            protocol_stats['udp'] += 1
                        elif isinstance(ip.data, dpkt.icmp.ICMP):
                            protocol_stats['icmp'] += 1
                        else:
                            protocol_stats['other'] += 1
                except:
                    continue
            
            # Add PCAP analysis
            analysis.update({
                "protocol_analysis": protocol_stats,
                "top_source_ips": dict(sorted(source_ips.items(), key=lambda x: x[1], reverse=True)[:10]),
                "top_destination_ips": dict(sorted(dest_ips.items(), key=lambda x: x[1], reverse=True)[:10]),
                "total_packets": sum(protocol_stats.values()),
                "file_type": "PCAP"
            })
            
        except Exception as e:
            analysis.update({
                "protocol_analysis": {"error": "Not a PCAP file or invalid format"},
                "top_source_ips": {},
                "top_destination_ips": {},
                "file_type": "Unknown"
            })
        
        return analysis
        
    except Exception as e:
        return {
            "error": str(e),
            "file_size": len(content),
            "timestamp": datetime.now().isoformat()
        }

# Add FastAPI routes
@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    try:
        contents = await file.read()
        file_obj = BytesIO(contents)
        analysis_result = analyze_file(file_obj)
        
        return JSONResponse({
            "message": "File uploaded successfully",
            "status": "success",
            "analysis": analysis_result
        })
    except Exception as e:
        return JSONResponse({
            "error": str(e)
        }, status_code=500)

# Vercel handler
handler = Handler 