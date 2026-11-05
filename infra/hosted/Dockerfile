# Hosted synthetic demonstration API + worker (Render). Build from the project root:
#   docker build -f infra/hosted/Dockerfile -t kapit-c2-api .
# No web/dist (Vercel serves it), no local runtime, keys, database or backups.
FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY backend/requirements.txt /app/backend/requirements.txt
RUN python -m pip install --no-cache-dir --only-binary=:all: -r /app/backend/requirements.txt
RUN groupadd --gid 10001 kapit && useradd --uid 10001 --gid kapit --create-home kapit
COPY --chown=kapit:kapit backend/ /app/backend/
COPY --chown=kapit:kapit infra/ /app/infra/
USER kapit
EXPOSE 10000
ENV PORT=10000
CMD ["python", "infra/hosted/hosted.py", "serve"]
