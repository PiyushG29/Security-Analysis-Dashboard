import os
import google.generativeai as genai
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

# Configure Gemini API
genai.configure(api_key=os.getenv('GEMINI_API_KEY'))

class AnalysisRequest(BaseModel):
    analysis: str

@app.post("/api/analyze")
async def analyze_threats(request: AnalysisRequest):
    try:
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
        
        # Generate response
        response = model.generate_content(prompt)
        
        return {"analysis": response.text}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 