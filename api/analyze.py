import os
import google.generativeai as genai
from fastapi import FastAPI, HTTPException, Request, UploadFile, File
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import logging
import json
from io import BytesIO
from datetime import datetime

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
        # This is a simplified analysis - you can integrate with your actual analyzers
        # from your asc_system/ directory as needed
        
        # Mock analysis result for demonstration
        analysis = {
            "file_size_bytes": file_obj.getbuffer().nbytes,
            "timestamp": str(datetime.now()),
            "summary": {
                "total_packets": 120,
                "protocols": {
                    "TCP": 85,
                    "UDP": 25,
                    "ICMP": 10,
                    "Other": 0
                },
                "top_ips": [
                    {"ip": "192.168.1.10", "count": 45},
                    {"ip": "10.0.0.5", "count": 32},
                    {"ip": "8.8.8.8", "count": 28}
                ],
                "potential_threats": [
                    {
                        "type": "Port Scan",
                        "confidence": "Medium",
                        "details": "Multiple connection attempts to different ports"
                    }
                ]
            }
        }
        
        return analysis
    except Exception as e:
        logger.error(f"Error analyzing file: {str(e)}")
        return {"error": str(e)}

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