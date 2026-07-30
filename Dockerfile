FROM python:3.11-slim

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=0

WORKDIR /app

RUN apt-get update -qq && apt-get install -qq -y --no-install-recommends \
    libffi-dev gcc curl ca-certificates && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/*

COPY requirements.txt .
RUN pip install -q -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]
