import sys
import os
import json
import time
import traceback
from typing import Dict, Any, List
import queue
from collections import defaultdict
from fastapi import FastAPI, Request, Response, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path

# Add the asc_system directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pandas as pd
try:
    from scapy.all import rdpcap
except ImportError:
    print("Warning: Scapy not installed. PCAP file analysis will be limited.")
    def rdpcap(file_path):
        raise ValueError("Scapy is not installed. Cannot analyze PCAP files.")

from src.detectors.anomaly_detector import AnomalyDetector
from src.analyzers.context_analyzer import ContextAnalyzer
from src.detectors.network_traffic_detector import NetworkTrafficDetector

app = FastAPI()

# Mount static files
static_path = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(static_path)), name="static")

# Setup templates
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

# Configure upload folder
UPLOAD_FOLDER = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'uploads'))
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Create queues for events and alerts
event_queue = queue.Queue()
alert_queue = queue.Queue()

# Default configuration
default_config = {
    'analysis_interval': 10,  # seconds
    'detection_window': 300,  # 5 minutes
    'alert_threshold': 80,    # score threshold for alerts
    'sensitivity': 2.5,      # standard deviations for anomaly detection
    'interface': 'default'   # network interface
}

def analyze_packets(packets: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze packets using the security system components."""
    try:
        # Initialize detectors with queues and config
        network_detector = NetworkTrafficDetector(event_queue=event_queue, config=default_config)
        anomaly_detector = AnomalyDetector(event_queue=event_queue, config=default_config)
        context_analyzer = ContextAnalyzer(alert_queue=alert_queue, config=default_config)

        # Start the detectors
        network_detector.on_start()
        anomaly_detector.on_start()

        # Initialize network detector stats
        current_time = time.time()
        network_detector.stats.update({
            'total_packets': 0,
            'bytes_received': 0,
            'packets_per_protocol': defaultdict(int),
            'connections': defaultdict(int),
            'unique_ips': set(),
            'packet_rate': 0.0,
            'last_update': current_time
        })

        # Process packets through network detector based on capture method
        raw_packets = [p['packet'] for p in packets if 'packet' in p]
        if raw_packets:
            # Since we're reading from a file, we'll use Scapy processing
            # regardless of the capture_method setting
            try:
                network_detector._process_packets_scapy(raw_packets)
            except Exception as e:
                # If Scapy processing fails, try a simplified analysis
                for packet in raw_packets:
                    try:
                        # Update basic statistics
                        network_detector.stats['total_packets'] += 1
                        
                        # Try to get packet length
                        if hasattr(packet, 'len'):
                            network_detector.stats['bytes_received'] += packet.len
                        
                        # Try to get IP information
                        if hasattr(packet, 'ip'):
                            src_ip = packet.ip.src
                            dst_ip = packet.ip.dst
                            network_detector.stats['unique_ips'].add(src_ip)
                            network_detector.stats['unique_ips'].add(dst_ip)
                        
                        # Try to get protocol information
                        if hasattr(packet, 'highest_layer'):
                            proto = packet.highest_layer
                            network_detector.stats['packets_per_protocol'][proto] += 1
                    except Exception:
                        continue

        # Update network detector stats
        elapsed = time.time() - current_time
        if elapsed > 0 and network_detector.stats['total_packets'] > 0:
            network_detector.stats['packet_rate'] = network_detector.stats['total_packets'] / elapsed

        # Get network traffic analysis results
        try:
            network_events = network_detector._analyze_traffic() if network_detector.stats['total_packets'] > 0 else []
        except Exception as e:
            network_events = []
            print(f"Warning: Error during traffic analysis: {e}")
        
        # Get anomaly detection results
        try:
            anomaly_results = anomaly_detector.detect()
        except Exception as e:
            anomaly_results = []
            print(f"Warning: Error during anomaly detection: {e}")

        # Analyze context
        context_data = {
            'packets': packets,
            'network_events': network_events or [],
            'anomalies': anomaly_results or [],
            'stats': {
                'total_packets': network_detector.stats['total_packets'],
                'packet_rate': float(network_detector.stats['packet_rate']),
                'bytes_received': network_detector.stats['bytes_received'],
                'unique_ips': len(network_detector.stats['unique_ips']),
                'protocols': dict(network_detector.stats['packets_per_protocol'])
            }
        }

        try:
            context_results = context_analyzer.analyze(context_data)
        except Exception as e:
            context_results = {}
            print(f"Warning: Error during context analysis: {e}")

        # Collect results
        results = {
            "network_events": network_events or [],
            "anomalies": anomaly_results or [],
            "context": context_results or {},
            "stats": context_data['stats']
        }

        # Check for any alerts in the alert queue
        alerts = []
        while not alert_queue.empty():
            try:
                alerts.append(alert_queue.get_nowait())
            except queue.Empty:
                break

        if alerts:
            results["alerts"] = alerts

        return results

    except Exception as e:
        error_details = traceback.format_exc()
        raise ValueError(f"Error analyzing packets: {str(e)}\nDetails: {error_details}")

def parse_file(file_path: str) -> List[Dict[str, Any]]:
    """Parse uploaded files and return structured data."""
    if not os.path.exists(file_path):
        raise ValueError(f"File not found: {file_path}")
        
    if file_path.endswith('.csv'):
        # Parse CSV file using pandas
        try:
            data = pd.read_csv(file_path)
            return data.to_dict(orient='records')
        except Exception as e:
            raise ValueError(f"Error parsing CSV file: {str(e)}")
    elif file_path.endswith('.pcap'):
        # Parse PCAP file using scapy
        try:
            packets = rdpcap(file_path)
            return [{"summary": packet.summary(), "time": packet.time, "packet": packet} for packet in packets]
        except Exception as e:
            raise ValueError(f"Error parsing PCAP file: {str(e)}")
    else:
        raise ValueError("Unsupported file type. Please upload a .csv or .pcap file.")

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.get("/api/status")
async def get_status():
    return JSONResponse(content={"status": "ok"})

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    try:
        if not file.filename.lower().endswith(('.csv', '.pcap')):
            raise HTTPException(status_code=400, detail="Unsupported file type. Please upload a .csv or .pcap file.")

        file_path = os.path.join(UPLOAD_FOLDER, file.filename)
        
        # Save the uploaded file
        with open(file_path, "wb") as buffer:
            content = await file.read()
            buffer.write(content)

        try:
            # Parse the uploaded file
            parsed_data = parse_file(file_path)
            
            # Analyze the data
            results = analyze_packets(parsed_data)

            return JSONResponse(content={
                "message": "File processed successfully",
                "results": results
            })

        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
        finally:
            # Clean up the uploaded file
            try:
                os.remove(file_path)
            except:
                pass

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

# For Vercel deployment
if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
