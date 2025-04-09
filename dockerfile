# Use official Python image
FROM python:3.12-slim

# Set work directory
WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y build-essential curl && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Define entrypoint
ENTRYPOINT ["python", "main.py"]