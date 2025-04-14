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

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# Configure Gemini API
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
if not GEMINI_API_KEY:
    logger.error("GEMINI_API_KEY environment variable is not set")
else:
    logger.info("GEMINI_API_KEY is set")
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        # Test the API key by making a simple request
        model = genai.GenerativeModel('gemini-pro')
        test_response = model.generate_content("Test")
        logger.info("Gemini API key verified successfully")
    except Exception as e:
        logger.error(f"Failed to configure Gemini API: {str(e)}")
        GEMINI_API_KEY = None

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

@app.post("/api/chat")
async def chat_with_ai(request: Request):
    try:
        if not GEMINI_API_KEY:
            return JSONResponse(
                status_code=500,
                content={
                    "error": True,
                    "response": "Chat is currently unavailable. Please check the API configuration."
                }
            )

        body = await request.json()
        if not body or 'message' not in body or 'context' not in body:
            return JSONResponse(
                status_code=400,
                content={
                    "error": True,
                    "response": "Invalid request format. Expected 'message' and 'context' fields."
                }
            )

        user_message = body['message']
        analysis_context = body['context']

        model = genai.GenerativeModel('gemini-pro')
        prompt = f"""You are a cybersecurity expert analyzing network traffic data. Here is the context of the analysis:

Analysis Context:
{analysis_context}

User Question: {user_message}

Please provide a detailed response that:
1. Directly addresses the user's question
2. References specific data from the analysis when relevant
3. Explains technical concepts in a clear way
4. Provides actionable recommendations if applicable
5. Highlights any security implications

Format your response in a clear, structured manner."""

        logger.info(f"Sending chat request to Gemini API")
        response = model.generate_content(prompt)
        
        if not response or not response.text:
            return JSONResponse(
                status_code=500,
                content={
                    "error": True,
                    "response": "No response generated. Please try again."
                }
            )

        ai_response = response.text.strip()
        logger.info("Successfully received response from Gemini API")
        
        return JSONResponse(
            status_code=200,
            content={
                "error": False,
                "response": ai_response
            }
        )

    except Exception as e:
        logger.error(f"Error in chat endpoint: {str(e)}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "error": True,
                "response": "An unexpected error occurred while processing your message."
            }
        )

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