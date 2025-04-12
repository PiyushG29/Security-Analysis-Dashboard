from fastapi import FastAPI, Request, UploadFile, File, Form
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
import os
import shutil
import json
import logging
from typing import Optional
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Get the directory where this file is located
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Create necessary directories if they don't exist
static_dir = BASE_DIR / "static"
static_dir.mkdir(exist_ok=True)

templates_dir = BASE_DIR / "templates"
templates_dir.mkdir(exist_ok=True)

# Mount static files only if directory exists
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Initialize templates
templates = Jinja2Templates(directory=str(templates_dir))

# Add handle method for Vercel
@app.middleware("http")
async def handle(request: Request, call_next):
    response = await call_next(request)
    return response

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/upload")
async def upload_file(file: UploadFile = File(...), file_type: str = Form(...)):
    try:
        # Create uploads directory if it doesn't exist
        upload_dir = BASE_DIR / "uploads"
        upload_dir.mkdir(exist_ok=True)
        
        # Save the file
        file_path = upload_dir / file.filename
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        return JSONResponse(
            status_code=200,
            content={"message": "File uploaded successfully", "filename": file.filename}
        )
    except Exception as e:
        logger.error(f"Error uploading file: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": "Failed to upload file"}
        )

@app.get("/download/{filename}")
async def download_file(filename: str):
    try:
        file_path = BASE_DIR / "uploads" / filename
        if not file_path.exists():
            return JSONResponse(
                status_code=404,
                content={"error": "File not found"}
            )
        return FileResponse(
            path=file_path,
            filename=filename,
            media_type="application/octet-stream"
        )
    except Exception as e:
        logger.error(f"Error downloading file: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": "Failed to download file"}
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
