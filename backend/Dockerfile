FROM python:3.11-slim

WORKDIR /app

# Install dependencies (Playwright needs system deps)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers and their dependencies
RUN playwright install chromium
RUN playwright install-deps chromium

# Copy the backend code and models
COPY . .

# Expose the API port
EXPOSE 8000

# Run in production mode
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
