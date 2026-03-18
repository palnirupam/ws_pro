FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt /app/requirements.txt
COPY requirements-prod.txt /app/requirements-prod.txt

RUN pip install --no-cache-dir -r /app/requirements.txt -r /app/requirements-prod.txt

COPY . /app

EXPOSE 5000 7000

# Default command starts the dashboard in production mode (gunicorn+eventlet)
CMD ["gunicorn", "-k", "eventlet", "-w", "1", "-b", "0.0.0.0:5000", "dashboard.app:app"]

