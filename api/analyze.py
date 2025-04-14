import os
import google.generativeai as genai
from fastapi import FastAPI, HTTPException, Request, UploadFile, File
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import logging
import json
from io import BytesIO
from datetime import datetime
import re
import dpkt
import socket
from dotenv import load_dotenv
import requests

# Load environment variables
load_dotenv()

# Get API key from environment
api_key = os.getenv('HUGGINGFACE_API_KEY')
if not api_key:
    raise ValueError("HUGGINGFACE_API_KEY environment variable is not set")

API_URL = "https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.2"
headers = {"Authorization": f"Bearer {api_key}"}

app = FastAPI()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AnalysisRequest(BaseModel):
    analysis: str

class ChatRequest(BaseModel):
    message: str
    context: str

def analyze_file(file_obj):
    """
    Analyze the uploaded file and return structured analysis results
    """
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

@app.post("/api/analyze/upload")
async def upload_file(file: UploadFile = File(...)):
    try:
        logger.info(f"Received file upload: {file.filename}")
        contents = await file.read()
        file_obj = BytesIO(contents)
        
        # Analyze the file
        analysis_result = analyze_file(file_obj)
        
        return JSONResponse({
            "message": "File uploaded successfully",
            "status": "success",
            "analysis": analysis_result
        })
    except Exception as e:
        logger.error(f"Error processing file upload: {str(e)}")
        return JSONResponse({
            "error": str(e)
        }, status_code=500)

def query(payload):
    response = requests.post(API_URL, headers=headers, json=payload)
    return response.json()

@app.post("/chat")
async def chat_with_ai(request: ChatRequest):
    try:
        # Format the prompt for the model
        prompt = f"""You are a cybersecurity expert analyzing network traffic data. 
        Please provide a detailed response to the following question:
        
        {request.message}
        
        Please:
        1. Address the question directly
        2. Provide technical explanations
        3. Include security implications
        4. Give actionable recommendations if applicable
        """
        
        payload = {
            "inputs": prompt,
            "parameters": {
                "max_new_tokens": 500,
                "temperature": 0.7,
                "top_p": 0.95,
                "do_sample": True
            }
        }
        
        response = query(payload)
        
        if isinstance(response, list) and len(response) > 0:
            return {"response": response[0]['generated_text']}
        elif isinstance(response, dict) and 'error' in response:
            raise HTTPException(status_code=500, detail=response['error'])
        else:
            raise HTTPException(status_code=500, detail="Unexpected response format from AI model")
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Add handler for Vercel
@app.middleware("http")
async def handle(request: Request, call_next):
    try:
        response = await call_next(request)
        return response
    except Exception as e:
        logger.error(f"Middleware error: {str(e)}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "error": True,
                "analysis": "Server error occurred while processing the request."
            }
        ) 