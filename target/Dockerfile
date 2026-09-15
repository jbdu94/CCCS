FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py logging_utils.py ./

ENV EVENT_LOG_PATH=/logs/events.jsonl
ENV MOCK_MODE=true

EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
