import os
import google.generativeai as genai
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import logging

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
    genai.configure(api_key=GEMINI_API_KEY)

class AnalysisRequest(BaseModel):
    analysis: str

@app.post("/api/analyze")
async def analyze_threats(request: AnalysisRequest):
    try:
        if not GEMINI_API_KEY:
            raise HTTPException(
                status_code=500,
                detail="Gemini API key is not configured. Please check environment variables."
            )

        # Initialize Gemini model
        model = genai.GenerativeModel('gemini-pro')
        
        # Create prompt for threat analysis
        prompt = f"""
        Analyze the following network traffic analysis for potential security threats:
        
        {request.analysis}
        
        Please provide:
        1. Potential security threats identified
        2. Risk level assessment
        3. Recommended actions
        4. Any suspicious patterns or anomalies
        
        Format the response in a clear, structured manner.
        """
        
        logger.info("Sending request to Gemini API")
        # Generate response
        response = model.generate_content(prompt)
        
        if not response or not response.text:
            raise HTTPException(
                status_code=500,
                detail="Empty response from Gemini API"
            )
            
        logger.info("Successfully received response from Gemini API")
        return {"analysis": response.text}
        
    except Exception as e:
        logger.error(f"Error in analyze_threats: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error analyzing threats: {str(e)}"
        ) 