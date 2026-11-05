FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY backend/requirements.txt /app/backend/requirements.txt
RUN python -m pip install --no-cache-dir --only-binary=:all: -r /app/backend/requirements.txt
RUN groupadd --gid 10001 kapit && useradd --uid 10001 --gid kapit --create-home kapit
RUN printf '%s\n' 'kapit-c2-local-m1' > /app/.kapit-m1-container && chmod 444 /app/.kapit-m1-container
COPY --chown=kapit:kapit backend/ /app/backend/
COPY --chown=kapit:kapit infra/ /app/infra/
COPY --chown=kapit:kapit web/dist/ /app/web/dist/
USER kapit
EXPOSE 8000
CMD ["python", "infra/container_entrypoint.py", "backend"]
