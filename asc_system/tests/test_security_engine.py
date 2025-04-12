import sys
import os
import pytest
import queue
import tempfile
from flask import Flask
from src.dashboard import app
from unittest.mock import patch
from scapy.all import wrpcap, Ether

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.core.engine import SecurityEngine
from src.core.config_manager import ConfigManager
from unittest.mock import MagicMock

@pytest.fixture
def mock_config():
    return {
        'detection': {
            'enabled_detectors': ['network', 'anomaly', 'port_scan', 'data_exfil', 'api_abuse'],
            'alert_threshold': 70
        },
        'engine': {
            'max_workers': 5
        }
    }

@pytest.fixture
def mock_event_queue():
    return queue.Queue(maxsize=1000)

@pytest.fixture
def security_engine(mock_config, mock_event_queue):
    engine = SecurityEngine(config=mock_config, mode="real-time", enable_ml=False)
    engine.event_queue = mock_event_queue
    return engine

def test_engine_initialization(security_engine):
    assert security_engine is not None
    assert security_engine.mode == "real-time"
    assert security_engine.enable_ml is False

def test_load_detectors(security_engine):
    security_engine._load_detectors()
    assert 'network' in security_engine.detectors
    assert 'anomaly' in security_engine.detectors
    assert 'port_scan' in security_engine.detectors
    assert 'data_exfil' in security_engine.detectors
    assert 'api_abuse' in security_engine.detectors

def test_event_processing(security_engine, mock_event_queue):
    mock_event = {'name': 'Test Event', 'severity': 3, 'score': 80}
    mock_event_queue.put(mock_event)

    def mock_analyze_event(event):
        assert event['name'] == 'Test Event'
        assert event['severity'] == 3
        assert event['score'] == 80

    security_engine._analyze_event = MagicMock(side_effect=mock_analyze_event)
    security_engine._process_event_queue()
    security_engine._analyze_event.assert_called_once_with(mock_event)

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_upload_pcap_file(client):
    # Create a temporary .pcap file
    temp_pcap = tempfile.NamedTemporaryFile(suffix='.pcap', delete=False)
    packet = Ether()  # Create a simple Ethernet packet
    wrpcap(temp_pcap.name, [packet])

    with open(temp_pcap.name, 'rb') as pcap_file:
        response = client.post('/upload', data={'file': pcap_file}, content_type='multipart/form-data')

    assert response.status_code == 200
    assert 'results' in response.json
    assert 'anomalies' in response.json['results']
    assert 'context' in response.json['results']