FROM python:3.12-slim

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Chromium and system dependencies required for headless browser execution
RUN playwright install --with-deps chromium

# Copy backend application, ML models, and configuration
COPY . .

# Expose the API port
EXPOSE 8000

# Run with production settings
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
