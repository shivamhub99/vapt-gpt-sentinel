FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY app.py .

EXPOSE 8080

CMD ["gunicorn", "-b", "0.0.0.0:8080", "--workers", "2", "app:app"]
