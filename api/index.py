import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from asc_system.src.dashboard import app

# Vercel requires a handler function
def handler(request, context):
    return app(request) 