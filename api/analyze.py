import os
import google.generativeai as genai
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import logging
import json

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

@app.post("/api/analyze")
async def analyze_threats(request: Request):
    try:
        if not GEMINI_API_KEY:
            return JSONResponse(
                status_code=500,
                content={
                    "error": True,
                    "analysis": "AI analysis is currently unavailable. Please check the API configuration."
                }
            )

        # Parse request body
        try:
            body = await request.json()
        except json.JSONDecodeError:
            return JSONResponse(
                status_code=400,
                content={
                    "error": True,
                    "analysis": "Invalid JSON in request body"
                }
            )

        if not body or 'analysis' not in body:
            return JSONResponse(
                status_code=400,
                content={
                    "error": True,
                    "analysis": "Invalid request format. Expected 'analysis' field in request body."
                }
            )

        analysis_data = body['analysis']
        logger.info(f"Received analysis data: {analysis_data[:100]}...")

        # Initialize Gemini model
        model = genai.GenerativeModel('gemini-pro')
        
        # Create prompt for threat analysis
        prompt = f"""
        Analyze the following network traffic analysis for potential security threats:
        
        {analysis_data}
        
        Please provide a structured analysis in the following format:

        POTENTIAL THREATS:
        - List key security threats identified
        
        RISK ASSESSMENT:
        - Overall risk level
        - Specific risks identified
        
        RECOMMENDED ACTIONS:
        - Immediate steps to take
        - Long-term security improvements
        
        SUSPICIOUS PATTERNS:
        - Unusual traffic patterns
        - Anomalies detected
        """
        
        logger.info("Sending request to Gemini API")
        try:
            response = model.generate_content(prompt)
            
            if not response or not response.text:
                return JSONResponse(
                    status_code=500,
                    content={
                        "error": True,
                        "analysis": "No analysis generated. Please try again."
                    }
                )
                
            logger.info("Successfully received response from Gemini API")
            return JSONResponse(
                status_code=200,
                content={
                    "error": False,
                    "analysis": response.text,
                    "chat_enabled": True
                }
            )
            
        except Exception as api_error:
            logger.error(f"Gemini API error: {str(api_error)}")
            return JSONResponse(
                status_code=500,
                content={
                    "error": True,
                    "analysis": "Unable to complete the analysis. Please try again later."
                }
            )
            
    except Exception as e:
        logger.error(f"Error in analyze_threats: {str(e)}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "error": True,
                "analysis": "An unexpected error occurred during analysis."
            }
        )

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

        # Parse request body
        try:
            body = await request.json()
        except json.JSONDecodeError:
            return JSONResponse(
                status_code=400,
                content={
                    "error": True,
                    "response": "Invalid JSON in request body"
                }
            )

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

        # Initialize Gemini model
        model = genai.GenerativeModel('gemini-pro')
        
        # Create a more detailed prompt for better responses
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

        logger.info(f"Sending chat request to Gemini API. User message: {user_message[:100]}...")
        
        try:
            # Generate response from Gemini
            response = model.generate_content(prompt)
            
            if not response or not response.text:
                return JSONResponse(
                    status_code=500,
                    content={
                        "error": True,
                        "response": "No response generated. Please try again."
                    }
                )

            # Format and clean the response
            ai_response = response.text.strip()
            
            logger.info("Successfully received response from Gemini API")
            return JSONResponse(
                status_code=200,
                content={
                    "error": False,
                    "response": ai_response
                }
            )

        except Exception as api_error:
            logger.error(f"Gemini API error: {str(api_error)}")
            return JSONResponse(
                status_code=500,
                content={
                    "error": True,
                    "response": "Unable to generate a response. Please try again."
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