import sys
import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Import the FastAPI app
from asc_system.src.dashboard import app

# Vercel serverless function handler
async def handler(request: Request):
    try:
        response = await app(request)
        return response
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": str(e)}
        ) 