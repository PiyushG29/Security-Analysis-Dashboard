import sys
import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from mangum import Mangum

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Import the FastAPI app
from asc_system.src.dashboard import app

# Create handler for Vercel
handler = Mangum(app, lifespan="off")  # Disable lifespan events for Vercel 