# NetTriage web app. The built UI is committed, so only Python is needed.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    NETTRIAGE_HOST=0.0.0.0

WORKDIR /app
COPY backend/requirements.txt backend/requirements.txt
RUN pip install -r backend/requirements.txt

COPY backend/nettriage backend/nettriage
COPY samples samples

# Run as an unprivileged user.
RUN useradd --create-home --uid 10001 nettriage
USER nettriage

WORKDIR /app/backend
# PORT is set by the platform (Railway); locally it falls back to 8765.
CMD ["python", "-m", "nettriage", "serve"]
