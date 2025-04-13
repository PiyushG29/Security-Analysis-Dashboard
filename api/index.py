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
                        display: flex;
                        flex-direction: row;
                        gap: 20px;
                        margin-top: 20px;
                        overflow-x: auto;
                        padding: 10px;
                    }
                    
                    .protocol-stat {
                        min-width: 200px;
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
                    
                    .ip-list {
                        display: flex;
                        flex-wrap: wrap;
                        gap: 10px;
                        margin-top: 10px;
                    }
                    
                    .ip-item {
                        background: linear-gradient(45deg, var(--primary-color), var(--secondary-color));
                        color: white;
                        padding: 8px 15px;
                        border-radius: 20px;
                        font-size: 0.9em;
                        display: flex;
                        align-items: center;
                        gap: 8px;
                        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                        transition: transform 0.2s ease;
                    }
                    
                    .ip-item:hover {
                        transform: translateY(-2px);
                        box-shadow: 0 4px 8px rgba(0,0,0,0.2);
                    }
                    
                    .ip-count {
                        background: rgba(255,255,255,0.2);
                        padding: 2px 8px;
                        border-radius: 10px;
                        font-size: 0.8em;
                    }
                    
                    .print-button {
                        position: fixed;
                        bottom: 20px;
                        right: 20px;
                        background: linear-gradient(45deg, var(--primary-color), var(--secondary-color));
                        color: white;
                        padding: 10px 20px;
                        border: none;
                        border-radius: 25px;
                        cursor: pointer;
                        font-size: 0.9em;
                        font-weight: 500;
                        transition: all 0.3s ease;
                        box-shadow: 0 2px 10px rgba(0,0,0,0.2);
                        display: flex;
                        align-items: center;
                        gap: 8px;
                        z-index: 1000;
                    }
                    
                    .print-button:hover {
                        transform: translateY(-2px);
                        box-shadow: 0 4px 15px rgba(0,0,0,0.3);
                    }
                    
                    .print-button svg {
                        width: 16px;
                        height: 16px;
                    }
                    
                    .chat-window {
                        display: none;
                        position: fixed;
                        top: 50%;
                        left: 50%;
                        transform: translate(-50%, -50%);
                        width: 80%;
                        max-width: 800px;
                        height: 80vh;
                        background: white;
                        border-radius: 12px;
                        box-shadow: 0 4px 20px rgba(0,0,0,0.2);
                        z-index: 1000;
                        padding: 20px;
                        flex-direction: column;
                    }
                    
                    .chat-header {
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        padding-bottom: 15px;
                        border-bottom: 1px solid var(--border-color);
                    }
                    
                    .chat-title {
                        font-size: 1.2em;
                        font-weight: 600;
                        color: var(--text-color);
                    }
                    
                    .chat-close {
                        background: none;
                        border: none;
                        color: var(--text-color);
                        cursor: pointer;
                        font-size: 1.5em;
                        padding: 5px;
                    }
                    
                    .chat-messages {
                        flex-grow: 1;
                        overflow-y: auto;
                        padding: 20px;
                        display: flex;
                        flex-direction: column;
                        gap: 12px;
                        background: rgba(248, 249, 250, 0.95);
                        border-radius: 8px;
                        margin: 15px 0;
                    }
                    
                    .chat-message {
                        padding: 12px 16px;
                        border-radius: 12px;
                        max-width: 80%;
                        margin: 8px 0;
                        line-height: 1.5;
                        font-size: 0.95em;
                    }
                    
                    .user-message {
                        background: linear-gradient(45deg, var(--primary-color), var(--secondary-color));
                        color: white;
                        align-self: flex-end;
                        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                    }
                    
                    .ai-message {
                        background: white;
                        color: var(--text-color);
                        align-self: flex-start;
                        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                        border: 1px solid rgba(0,0,0,0.1);
                    }
                    
                    .chat-message.loading {
                        background: rgba(var(--primary-color-rgb), 0.1);
                        border: none;
                        color: var(--text-color);
                        display: flex;
                        align-items: center;
                        gap: 10px;
                        font-style: italic;
                    }
                    
                    .chat-message.error {
                        background: rgba(255, 0, 0, 0.05);
                        color: #ff3333;
                        border: 1px solid rgba(255, 0, 0, 0.1);
                    }
                    
                    .chat-input-container {
                        display: flex;
                        gap: 10px;
                        padding: 15px;
                        background: white;
                        border-top: 1px solid var(--border-color);
                        border-radius: 0 0 12px 12px;
                    }
                    
                    .chat-input {
                        flex-grow: 1;
                        padding: 10px;
                        border: 1px solid var(--border-color);
                        border-radius: 8px;
                        background: var(--input-bg);
                        color: var(--text-color);
                        font-size: 0.9em;
                    }
                    
                    .chat-send {
                        padding: 10px 20px;
                        background: var(--primary-color);
                        color: white;
                        border: none;
                        border-radius: 8px;
                        cursor: pointer;
                        font-weight: 500;
                        transition: all 0.3s ease;
                    }
                    
                    .chat-send:hover {
                        background: var(--primary-color-dark);
                    }
                    
                    .chat-overlay {
                        display: none;
                        position: fixed;
                        top: 0;
                        left: 0;
                        right: 0;
                        bottom: 0;
                        background: rgba(0,0,0,0.5);
                        z-index: 999;
                    }
                    
                    @media print {
                        body * {
                            visibility: hidden;
                        }
                        .analysis-card, .analysis-card * {
                            visibility: visible;
                        }
                        .analysis-card {
                            position: absolute;
                            left: 0;
                            top: 0;
                            width: 100%;
                        }
                        .print-button {
                            display: none;
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
                            
                            const response = await fetch('/api/upload', {
                                method: 'POST',
                                body: formData
                            });
                            
                            if (!response.ok) {
                                throw new Error('Upload failed');
                            }
                            
                            const data = await response.json();
                            
                            if (data.error) {
                                showError(data.error);
                            } else {
                                showSuccess('File uploaded successfully!');
                                displayAnalysis(data);
                            }
                        } catch (error) {
                            console.error('Upload error:', error);
                            showError(error.message || 'An error occurred during upload');
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
                            // Store the analysis for chat context
                            window.lastAnalysis = JSON.stringify(data.analysis);
                            
                            // Display basic file information first
                            const basicInfo = document.createElement('div');
                            basicInfo.className = 'analysis-item';
                            basicInfo.innerHTML = `
                                <div class="analysis-item-title">File Information</div>
                                <div class="analysis-item-value">
                                    <p>Size: ${formatBytes(data.analysis.file_size)}</p>
                                    <p>Type: ${data.analysis.file_type || 'Unknown'}</p>
                                    ${data.analysis.line_count ? `<p>Lines: ${data.analysis.line_count}</p>` : ''}
                                </div>
                            `;
                            analysisContent.appendChild(basicInfo);
                            
                            // Display protocol analysis if available
                            if (data.analysis.protocol_analysis && !data.analysis.protocol_analysis.error) {
                                const protocolStats = data.analysis.protocol_analysis;
                                const total = Object.values(protocolStats).reduce((a, b) => a + b, 0);
                                
                                const protocolHTML = `
                                    <div class="protocol-analysis">
                                        <div class="protocol-header">
                                            <h2 class="protocol-title">Protocol Analysis</h2>
                                            <div>Total Packets: ${total}</div>
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
                                    </div>
                                `;
                                
                                analysisContent.innerHTML += protocolHTML;
                            }
                            
                            // Add IP analysis
                            if (data.analysis.top_source_ips || data.analysis.top_destination_ips) {
                                const ipAnalysis = document.createElement('div');
                                ipAnalysis.className = 'analysis-item';
                                ipAnalysis.innerHTML = `
                                    <div class="analysis-item-title">Network Traffic Analysis</div>
                                    <div class="ip-analysis">
                                        ${Object.keys(data.analysis.top_source_ips).length > 0 ? `
                                            <div class="ip-section">
                                                <h3>Top Source IPs</h3>
                                                <div class="ip-list">
                                                    ${Object.entries(data.analysis.top_source_ips)
                                                        .map(([ip, count]) => `
                                                            <div class="ip-item">
                                                                <span>${ip}</span>
                                                                <span class="ip-count">${count}</span>
                                                            </div>
                                                        `).join('')}
                                                </div>
                                            </div>
                                        ` : ''}
                                        
                                        ${Object.keys(data.analysis.top_destination_ips).length > 0 ? `
                                            <div class="ip-section">
                                                <h3>Top Destination IPs</h3>
                                                <div class="ip-list">
                                                    ${Object.entries(data.analysis.top_destination_ips)
                                                        .map(([ip, count]) => `
                                                            <div class="ip-item">
                                                                <span>${ip}</span>
                                                                <span class="ip-count">${count}</span>
                                                            </div>
                                                        `).join('')}
                                                </div>
                                            </div>
                                        ` : ''}
                                    </div>
                                `;
                                analysisContent.appendChild(ipAnalysis);
                            }
                            
                            // Add AI analysis section
                            const aiSection = document.createElement('div');
                            aiSection.className = 'ai-analysis';
                            aiSection.innerHTML = `
                                <div class="ai-header">
                                    <h2 class="ai-title">AI Threat Analysis</h2>
                                    <button class="chat-button" onclick="openChat()">
                                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                            <path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/>
                                        </svg>
                                        Discuss Analysis
                                    </button>
                                </div>
                            `;
                            analysisContent.appendChild(aiSection);
                        }
                        
                        // Show the analysis card
                        analysisCard.classList.add('show');
                    }
                    
                    function formatBytes(bytes) {
                        if (bytes === 0) return '0 Bytes';
                        const k = 1024;
                        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
                        const i = Math.floor(Math.log(bytes) / Math.log(k));
                        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
                    }
                    
                    function createChatInterface() {
                        // Remove existing chat interface if any
                        const existingChat = document.getElementById('chatInterface');
                        if (existingChat) {
                            existingChat.remove();
                        }
                        
                        const chatInterface = document.createElement('div');
                        chatInterface.id = 'chatInterface';
                        chatInterface.innerHTML = `
                            <div class="chat-overlay" id="chatOverlay" onclick="closeChat()"></div>
                            <div class="chat-window" id="chatWindow">
                                <div class="chat-header">
                                    <div class="chat-title">Discuss Analysis with AI</div>
                                    <button class="chat-close" onclick="closeChat()">&times;</button>
                                </div>
                                <div class="chat-messages" id="chatMessages"></div>
                                <div class="chat-input-container">
                                    <input type="text" class="chat-input" id="chatInput" 
                                           placeholder="Ask a question about the analysis..."
                                           onkeypress="if(event.key === 'Enter') sendMessage()">
                                    <button class="chat-send" onclick="sendMessage()">Send</button>
                                </div>
                            </div>
                        `;
                        document.body.appendChild(chatInterface);
                    }
                    
                    function openChat() {
                        createChatInterface();
                        document.getElementById('chatOverlay').style.display = 'block';
                        document.getElementById('chatWindow').style.display = 'flex';
                        document.getElementById('chatInput').focus();
                    }
                    
                    function closeChat() {
                        const chatOverlay = document.getElementById('chatOverlay');
                        const chatWindow = document.getElementById('chatWindow');
                        if (chatOverlay) chatOverlay.style.display = 'none';
                        if (chatWindow) chatWindow.style.display = 'none';
                    }
                    
                    async function sendMessage() {
                        const input = document.getElementById('chatInput');
                        const message = input.value.trim();
                        
                        if (!message) return;
                        
                        // Clear input
                        input.value = '';
                        
                        // Add user message to chat
                        const chatMessages = document.getElementById('chatMessages');
                        const userMessageDiv = document.createElement('div');
                        userMessageDiv.className = 'chat-message user-message';
                        userMessageDiv.textContent = message;
                        chatMessages.appendChild(userMessageDiv);
                        
                        try {
                            // Add loading message
                            const loadingDiv = document.createElement('div');
                            loadingDiv.className = 'chat-message ai-message loading';
                            loadingDiv.innerHTML = `
                                <div class="loading-spinner"></div>
                                <span>Analyzing...</span>
                            `;
                            chatMessages.appendChild(loadingDiv);
                            
                            // Send message to API
                            const response = await fetch('/api/chat', {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json',
                                },
                                body: JSON.stringify({
                                    message: message,
                                    context: window.lastAnalysis || ''
                                })
                            });
                            
                            // Remove loading message
                            loadingDiv.remove();
                            
                            if (!response.ok) {
                                throw new Error('Failed to get response from server');
                            }
                            
                            const data = await response.json();
                            
                            // Add AI response to chat
                            const aiMessageDiv = document.createElement('div');
                            aiMessageDiv.className = 'chat-message ai-message';
                            
                            if (data.error) {
                                aiMessageDiv.className += ' error';
                                aiMessageDiv.textContent = data.response || 'Error: Unable to get response';
                            } else {
                                const formattedResponse = data.response.replace(/\n/g, '<br>');
                                aiMessageDiv.innerHTML = formattedResponse;
                            }
                            
                            chatMessages.appendChild(aiMessageDiv);
                            
                            // Scroll to bottom
                            chatMessages.scrollTop = chatMessages.scrollHeight;
                            
                        } catch (error) {
                            console.error('Error sending message:', error);
                            const errorDiv = document.createElement('div');
                            errorDiv.className = 'chat-message ai-message error';
                            errorDiv.textContent = error.message || 'Error sending message. Please try again.';
                            chatMessages.appendChild(errorDiv);
                        }
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