FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/app

COPY api/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY api/app.py /app/api/app.py
COPY sims/common /app/common

CMD ["uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "8000"]