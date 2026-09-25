FROM python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/opt/vibesecur
COPY requirements.lock /opt/vibesecur/requirements.lock
RUN pip install --no-cache-dir -r /opt/vibesecur/requirements.lock
COPY payment_app /opt/vibesecur/payment_app
USER 65532:65532
WORKDIR /opt/vibesecur
CMD ["python", "-m", "uvicorn", "payment_app.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
