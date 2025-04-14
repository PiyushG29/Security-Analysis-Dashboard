from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from typing import List, Dict, Any

app = FastAPI(title="Cybersecurity Threat Dashboard")

# Mock data for detected threats (replace with real data integration)
detected_threats = [
    {
        "id": 1,
        "name": "Anomaly Detected",
        "type": "anomaly.statistical",
        "severity": 3,
        "score": 85,
        "details": {
            "anomalous_features": ["packet_rate", "protocol_entropy"],
            "max_z_score": 3.2,
            "total_z_score": 5.8,
        },
    },
    {
        "id": 2,
        "name": "DDoS Attack Detected",
        "type": "anomaly.signature.dos",
        "severity": 4,
        "score": 92,
        "details": {
            "value": 0.7,
            "threshold": 0.5,
            "category": "dos",
        },
    },
]

@app.get("/threats", response_model=List[Dict[str, Any]])
def get_detected_threats():
    """Endpoint to fetch detected threats."""
    return JSONResponse(content=detected_threats)

@app.get("/status", response_model=Dict[str, Any])
def get_system_status():
    """Endpoint to fetch system status."""
    return JSONResponse(
        content={
            "status": "running",
            "uptime": "72 hours",
            "detectors_active": 5,
            "responders_active": 4,
        }
    )

# Serve static files
import os
import pathlib

# Get the absolute path to the static directory
base_dir = pathlib.Path(__file__).parent.absolute()
static_dir = os.path.join(base_dir, "static")
templates_dir = os.path.join(base_dir, "templates")

# Mount static directory
app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Setup templates
templates = Jinja2Templates(directory=templates_dir)

@app.get("/dashboard", response_class=HTMLResponse)
def serve_dashboard(request: Request):
    """Serve the interactive dashboard."""
    try:
        return templates.TemplateResponse("dashboard.html", {"request": request})
    except Exception as e:
        return HTMLResponse(content=f"Error loading dashboard: {str(e)}")

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
