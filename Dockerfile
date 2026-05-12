FROM python:3.11-slim

# Install system dependencies for scapy and other libs
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Ensure data and model directories exist
RUN mkdir -p data/cicids model

# Environment variables
ENV ICTDS_SECRET_KEY=""
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

EXPOSE 5001

# Using eventlet worker for SocketIO support
CMD ["gunicorn", "--worker-class", "eventlet", "-w", "1", "-b", "0.0.0.0:5001", "app:app"]
