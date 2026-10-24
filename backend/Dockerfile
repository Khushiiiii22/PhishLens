FROM python:3.12-slim

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Configure shared location for Playwright browsers
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# Install Chromium and system dependencies required for headless browser execution
RUN playwright install --with-deps chromium && chmod -R 755 /ms-playwright

# Create non-root application user
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser

# Copy backend application, ML models, and configuration
COPY . .
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose the API port
EXPOSE 8000

# Run with production settings
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

