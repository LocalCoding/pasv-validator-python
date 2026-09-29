FROM python:3.11-slim

# tini as PID 1 reaps processes orphaned by solutions; uvicorn as PID 1 leaves them as zombies
RUN apt-get update && apt-get install -y --no-install-recommends tini && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

ENV NODE_ENV=prod
ENV PORT=7001
ENV PYTHONUNBUFFERED=1

EXPOSE 7001

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-m", "uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "7001"]
