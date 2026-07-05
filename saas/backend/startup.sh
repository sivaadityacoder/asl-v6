#!/bin/bash
echo "Starting custom startup script..."

# Install git for repository cloning
echo "Installing git..."
apt-get update && apt-get install -y git

cd /home/site/wwwroot

# Create virtual environment if it doesn't exist
if [ ! -d "antenv" ]; then
    echo "Creating virtual environment..."
    python -m venv antenv
fi

# Activate and install dependencies
source antenv/bin/activate
echo "Installing dependencies..."
pip install -r requirements.txt

# Start the application
echo "Starting FastAPI server..."
uvicorn app.main:app --host 0.0.0.0 --port 8000
