import sys
import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from http.server import BaseHTTPRequestHandler
import json
import base64
import re
from datetime import datetime
import socket

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
                        --primary-color: #2196F3;
                        --secondary-color: #1976D2;
                        --accent-color: #FF9800;
                        --success-color: #4CAF50;
                        --error-color: #f44336;
                        --warning-color: #FFC107;
                        --info-color: #00BCD4;
                        --background-color: #f5f5f5;
                        --text-color: #333;
                        --card-shadow: 0 4px 6px rgba(0,0,0,0.1);
                        --hover-shadow: 0 8px 15px rgba(0,0,0,0.2);
                        
                        /* Protocol colors */
                        --tcp-color: #2196F3;
                        --udp-color: #FF9800;
                        --icmp-color: #4CAF50;
                        --other-color: #9C27B0;
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
                        background: linear-gradient(135deg, #f5f7fa 0%, #e3e9f2 100%);
                        color: var(--text-color);
                        min-height: 100vh;
                    }
                    
                    .container {
                        background-color: rgba(255, 255, 255, 0.95);
                        padding: 40px;
                        border-radius: 20px;
                        box-shadow: var(--card-shadow);
                        animation: fadeIn 0.8s ease-in-out;
                        backdrop-filter: blur(10px);
                        border: 1px solid rgba(255, 255, 255, 0.2);
                    }
                    
                    @keyframes fadeIn {
                        from { 
                            opacity: 0; 
                            transform: translateY(30px) scale(0.95);
                        }
                        to { 
                            opacity: 1; 
                            transform: translateY(0) scale(1);
                        }
                    }
                    
                    h1 {
                        color: var(--text-color);
                        text-align: center;
                        margin-bottom: 40px;
                        font-size: 2.5em;
                        font-weight: 700;
                        background: linear-gradient(45deg, var(--primary-color), var(--accent-color));
                        -webkit-background-clip: text;
                        -webkit-text-fill-color: transparent;
                        animation: glow 2s ease-in-out infinite alternate;
                    }
                    
                    @keyframes glow {
                        from {
                            text-shadow: 0 0 10px rgba(76, 175, 80, 0.5);
                        }
                        to {
                            text-shadow: 0 0 20px rgba(76, 175, 80, 0.8);
                        }
                    }
                    
                    .upload-section {
                        display: flex;
                        flex-direction: column;
                        gap: 30px;
                        align-items: center;
                        margin-bottom: 40px;
                        position: relative;
                    }
                    
                    .file-input-container {
                        width: 100%;
                        max-width: 500px;
                        position: relative;
                        transition: transform 0.3s ease;
                    }
                    
                    .file-input-container:hover {
                        transform: translateY(-5px);
                    }
                    
                    .file-input {
                        width: 100%;
                        padding: 30px;
                        border: 3px dashed #ccc;
                        border-radius: 15px;
                        text-align: center;
                        cursor: pointer;
                        transition: all 0.3s ease;
                        background-color: rgba(250, 250, 250, 0.8);
                        font-size: 1.1em;
                        position: relative;
                        overflow: hidden;
                    }
                    
                    .file-input::before {
                        content: '';
                        position: absolute;
                        top: 0;
                        left: -100%;
                        width: 100%;
                        height: 100%;
                        background: linear-gradient(
                            90deg,
                            transparent,
                            rgba(255, 255, 255, 0.4),
                            transparent
                        );
                        transition: 0.5s;
                    }
                    
                    .file-input:hover::before {
                        left: 100%;
                    }
                    
                    .file-input:hover {
                        border-color: var(--primary-color);
                        background-color: rgba(240, 240, 240, 0.9);
                        box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                    }
                    
                    .file-input.dragover {
                        border-color: var(--primary-color);
                        background-color: rgba(232, 245, 233, 0.9);
                        transform: scale(1.02);
                    }
                    
                    .submit-btn {
                        background: linear-gradient(45deg, var(--primary-color), var(--secondary-color));
                        color: white;
                        padding: 18px 35px;
                        border: none;
                        border-radius: 12px;
                        cursor: pointer;
                        font-size: 1.2em;
                        font-weight: 600;
                        transition: all 0.3s ease;
                        box-shadow: var(--card-shadow);
                        position: relative;
                        overflow: hidden;
                    }
                    
                    .submit-btn::before {
                        content: '';
                        position: absolute;
                        top: 0;
                        left: -100%;
                        width: 100%;
                        height: 100%;
                        background: linear-gradient(
                            90deg,
                            transparent,
                            rgba(255, 255, 255, 0.4),
                            transparent
                        );
                        transition: 0.5s;
                    }
                    
                    .submit-btn:hover::before {
                        left: 100%;
                    }
                    
                    .submit-btn:hover {
                        transform: translateY(-3px);
                        box-shadow: var(--hover-shadow);
                    }
                    
                    .submit-btn:active {
                        transform: translateY(1px);
                    }
                    
                    .loading {
                        display: none;
                        text-align: center;
                        margin: 30px 0;
                    }
                    
                    .loading-spinner {
                        width: 50px;
                        height: 50px;
                        border: 5px solid #f3f3f3;
                        border-top: 5px solid var(--primary-color);
                        border-radius: 50%;
                        animation: spin 1s linear infinite;
                        margin: 0 auto;
                        box-shadow: 0 0 10px rgba(76, 175, 80, 0.3);
                    }
                    
                    @keyframes spin {
                        0% { transform: rotate(0deg); }
                        100% { transform: rotate(360deg); }
                    }
                    
                    .analysis-card {
                        background-color: rgba(255, 255, 255, 0.95);
                        border-radius: 15px;
                        padding: 25px;
                        margin-top: 30px;
                        box-shadow: var(--card-shadow);
                        display: none;
                        backdrop-filter: blur(10px);
                        border: 1px solid rgba(255, 255, 255, 0.2);
                    }
                    
                    .analysis-card.show {
                        display: block;
                        animation: slideIn 0.5s ease-out;
                    }
                    
                    @keyframes slideIn {
                        from { 
                            opacity: 0;
                            transform: translateX(-30px);
                        }
                        to { 
                            opacity: 1;
                            transform: translateX(0);
                        }
                    }
                    
                    .analysis-header {
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        margin-bottom: 20px;
                        padding-bottom: 15px;
                        border-bottom: 2px solid rgba(76, 175, 80, 0.1);
                    }
                    
                    .analysis-title {
                        font-size: 1.4em;
                        font-weight: 600;
                        color: var(--primary-color);
                    }
                    
                    .analysis-content {
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
                        gap: 25px;
                    }
                    
                    .analysis-item {
                        background-color: rgba(248, 249, 250, 0.8);
                        padding: 20px;
                        border-radius: 12px;
                        transition: all 0.3s ease;
                        border: 1px solid rgba(0,0,0,0.05);
                    }
                    
                    .analysis-item:hover {
                        transform: translateY(-5px);
                        box-shadow: var(--hover-shadow);
                        background-color: white;
                    }
                    
                    .analysis-item-title {
                        font-weight: 600;
                        margin-bottom: 15px;
                        color: var(--primary-color);
                        font-size: 1.1em;
                    }
                    
                    .analysis-item-value {
                        font-size: 1.2em;
                        color: var(--text-color);
                    }
                    
                    .error-message, .success-message {
                        padding: 20px;
                        border-radius: 12px;
                        margin-top: 25px;
                        display: none;
                        animation: fadeIn 0.3s ease-out;
                        box-shadow: var(--card-shadow);
                    }
                    
                    .error-message {
                        background-color: rgba(244, 67, 54, 0.1);
                        color: var(--error-color);
                        border: 1px solid rgba(244, 67, 54, 0.2);
                    }
                    
                    .success-message {
                        background-color: rgba(76, 175, 80, 0.1);
                        color: var(--success-color);
                        border: 1px solid rgba(76, 175, 80, 0.2);
                    }
                    
                    .protocol-analysis {
                        margin-top: 30px;
                        padding: 25px;
                        background: white;
                        border-radius: 15px;
                        box-shadow: var(--card-shadow);
                        animation: slideIn 0.5s ease-out;
                    }
                    
                    .protocol-header {
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        margin-bottom: 20px;
                    }
                    
                    .protocol-title {
                        font-size: 1.4em;
                        font-weight: 600;
                        color: var(--primary-color);
                    }
                    
                    .protocol-stats {
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                        gap: 20px;
                        margin-top: 20px;
                    }
                    
                    .protocol-stat {
                        padding: 20px;
                        border-radius: 12px;
                        color: white;
                        text-align: center;
                        transition: transform 0.3s ease;
                        position: relative;
                        overflow: hidden;
                    }
                    
                    .protocol-stat::before {
                        content: '';
                        position: absolute;
                        top: 0;
                        left: -100%;
                        width: 100%;
                        height: 100%;
                        background: linear-gradient(
                            90deg,
                            transparent,
                            rgba(255, 255, 255, 0.2),
                            transparent
                        );
                        transition: 0.5s;
                    }
                    
                    .protocol-stat:hover::before {
                        left: 100%;
                    }
                    
                    .protocol-stat:hover {
                        transform: translateY(-5px);
                    }
                    
                    .protocol-stat.tcp {
                        background: linear-gradient(45deg, var(--tcp-color), #1565C0);
                    }
                    
                    .protocol-stat.udp {
                        background: linear-gradient(45deg, var(--udp-color), #F57C00);
                    }
                    
                    .protocol-stat.icmp {
                        background: linear-gradient(45deg, var(--icmp-color), #2E7D32);
                    }
                    
                    .protocol-stat.other {
                        background: linear-gradient(45deg, var(--other-color), #6A1B9A);
                    }
                    
                    .protocol-name {
                        font-size: 1.2em;
                        font-weight: 600;
                        margin-bottom: 10px;
                    }
                    
                    .protocol-count {
                        font-size: 2em;
                        font-weight: 700;
                    }
                    
                    .protocol-percentage {
                        font-size: 1.1em;
                        opacity: 0.9;
                        margin-top: 10px;
                    }
                    
                    .protocol-chart {
                        margin-top: 30px;
                        height: 200px;
                        display: flex;
                        align-items: flex-end;
                        gap: 10px;
                        padding: 20px;
                        background: rgba(255, 255, 255, 0.8);
                        border-radius: 12px;
                    }
                    
                    .chart-bar {
                        flex: 1;
                        background: linear-gradient(to top, var(--primary-color), var(--secondary-color));
                        border-radius: 8px 8px 0 0;
                        transition: height 0.5s ease-out;
                        position: relative;
                        min-width: 40px;
                    }
                    
                    .chart-bar::after {
                        content: attr(data-count);
                        position: absolute;
                        top: -30px;
                        left: 50%;
                        transform: translateX(-50%);
                        background: rgba(0, 0, 0, 0.8);
                        color: white;
                        padding: 5px 10px;
                        border-radius: 4px;
                        font-size: 0.9em;
                        opacity: 0;
                        transition: opacity 0.3s ease;
                    }
                    
                    .chart-bar:hover::after {
                        opacity: 1;
                    }
                    
                    .chart-bar.tcp { background: linear-gradient(to top, var(--tcp-color), #1565C0); }
                    .chart-bar.udp { background: linear-gradient(to top, var(--udp-color), #F57C00); }
                    .chart-bar.icmp { background: linear-gradient(to top, var(--icmp-color), #2E7D32); }
                    .chart-bar.other { background: linear-gradient(to top, var(--other-color), #6A1B9A); }
                    
                    @keyframes growBar {
                        from { height: 0; }
                        to { height: var(--target-height); }
                    }
                    
                    @media (max-width: 768px) {
                        .container {
                            padding: 20px;
                        }
                        
                        h1 {
                            font-size: 2em;
                        }
                        
                        .analysis-content {
                            grid-template-columns: 1fr;
                        }
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
                            // Display protocol analysis if available
                            if (data.analysis.protocol_analysis) {
                                const protocolStats = data.analysis.protocol_analysis;
                                const total = Object.values(protocolStats).reduce((a, b) => a + b, 0);
                                
                                const protocolHTML = `
                                    <div class="protocol-analysis">
                                        <div class="protocol-header">
                                            <h2 class="protocol-title">Protocol Analysis</h2>
                                        </div>
                                        <div class="protocol-stats">
                                            ${Object.entries(protocolStats).map(([protocol, count]) => `
                                                <div class="protocol-stat ${protocol.toLowerCase()}">
                                                    <div class="protocol-name">${protocol.toUpperCase()}</div>
                                                    <div class="protocol-count">${count}</div>
                                                    <div class="protocol-percentage">
                                                        ${((count / total) * 100).toFixed(1)}%
                                                    </div>
                                                </div>
                                            `).join('')}
                                        </div>
                                        <div class="protocol-chart">
                                            ${Object.entries(protocolStats).map(([protocol, count]) => `
                                                <div class="chart-bar ${protocol.toLowerCase()}"
                                                     style="height: ${(count / total) * 100}%"
                                                     data-count="${count}">
                                                </div>
                                            `).join('')}
                                        </div>
                                    </div>
                                `;
                                
                                analysisContent.innerHTML += protocolHTML;
                            }
                            
                            // Add other analysis items
                            Object.entries(data.analysis).forEach(([key, value]) => {
                                if (key !== 'protocol_analysis') {
                                    const item = document.createElement('div');
                                    item.className = 'analysis-item';
                                    item.innerHTML = `
                                        <div class="analysis-item-title">${formatKey(key)}</div>
                                        <div class="analysis-item-value">${formatValue(value)}</div>
                                    `;
                                    analysisContent.appendChild(item);
                                }
                            });
                        }
                        
                        // Show the analysis card
                        analysisCard.classList.add('show');
                        
                        // Animate chart bars
                        setTimeout(() => {
                            document.querySelectorAll('.chart-bar').forEach(bar => {
                                bar.style.animation = `growBar 1s ease-out forwards`;
                            });
                        }, 100);
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
                from io import BytesIO
                import dpkt
                
                # Create a BytesIO object from the content
                pcap_file = BytesIO(content)
                
                # Create a PCAP reader
                pcap = dpkt.pcap.Reader(pcap_file)
                
                # Initialize protocol counters
                protocol_stats = {
                    'tcp': 0,
                    'udp': 0,
                    'icmp': 0,
                    'other': 0
                }
                
                # Initialize IP counters
                source_ips = {}
                dest_ips = {}
                
                # Analyze each packet
                for timestamp, buf in pcap:
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        if isinstance(eth.data, dpkt.ip.IP):
                            ip = eth.data
                            
                            # Count source and destination IPs
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
                
                # Add PCAP-specific analysis
                analysis.update({
                    "protocol_analysis": protocol_stats,
                    "top_source_ips": dict(sorted(source_ips.items(), key=lambda x: x[1], reverse=True)[:10]),
                    "top_destination_ips": dict(sorted(dest_ips.items(), key=lambda x: x[1], reverse=True)[:10]),
                    "total_packets": sum(protocol_stats.values()),
                    "file_type": "PCAP"
                })
                
            except Exception as e:
                # If not a PCAP file, try other analysis
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

# Vercel requires this specific handler
handler = Handler 