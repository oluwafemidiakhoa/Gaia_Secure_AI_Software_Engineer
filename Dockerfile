FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN python -m pip install --upgrade pip \
    && python -m pip install . \
    && python -c "import jwt, cryptography; print('PUBLISHER_RUNTIME_DEPS: PASS')"

RUN useradd --create-home --uid 10001 gaia
USER gaia

EXPOSE 8080

CMD ["sh", "-c", "python -m http.server ${PORT:-8080} --directory /tmp"]
