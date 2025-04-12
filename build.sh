#!/bin/bash
echo "Installing Python dependencies..."
pip install --upgrade pip
pip install numpy==1.22.0
pip install scipy==1.8.0
pip install scikit-learn==1.0.2
pip install -r requirements.txt
echo "Installation complete!" 