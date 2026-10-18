# syntax=docker/dockerfile:1
FROM python:3.14-slim AS build
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.14-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 MG_ENV=prod PORT=8080
WORKDIR /app
COPY --from=build /install /usr/local
COPY app ./app
# Run as an unprivileged user; the app needs no writable filesystem.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin mailguard
USER 10001
EXPOSE 8080
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT} --no-server-header --proxy-headers"]
