FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY backend ./backend
COPY scripts ./scripts
COPY models ./models
COPY datasets ./datasets
COPY alembic ./alembic
COPY alembic.ini ./alembic.ini
COPY test-fixtures ./test-fixtures
COPY .env.example ./.env.example

# Fresh container DB lives in the persisted volume (see compose). Existing
# database files must adopt the baseline first: alembic stamp head.
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4)"

CMD ["python", "-m", "uvicorn", "backend.app.main:app", "--host", "127.0.0.1", "--port", "8000"]
