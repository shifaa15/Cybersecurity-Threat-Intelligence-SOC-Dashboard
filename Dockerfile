FROM python:3.11-slim

WORKDIR /app

COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend backend
COPY frontend frontend

WORKDIR /app/backend

ENV PORT=8000
EXPOSE 8000

# --workers 1 is intentional, not a placeholder: the stream processor's
# active-incident state, campaign state, and WebSocket connection list all
# live in a single process, and the SQLite file assumes one writer. Scale
# this service vertically or put a queue/DB in front of it before running
# more than one worker/replica — see README "Deploying" section.
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT} --workers 1"]
