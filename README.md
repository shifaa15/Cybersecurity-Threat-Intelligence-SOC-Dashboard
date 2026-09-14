# Sentry Deck — SOC Threat Intelligence Dashboard

An end-to-end Security Operations Center dashboard: a Python backend that
simulates a live SIEM event stream, enriches it against MITRE ATT&CK,
scores severity, correlates events into incidents, and pushes everything
to a real-time web dashboard over WebSockets.

## What it does

- **Stream processing pipeline** (`backend/stream_processor.py`): a continuous
  asyncio loop that ingests synthetic security events (mostly background
  noise, punctuated by scripted multi-stage attack campaigns — e.g. brute
  force → lateral movement → credential dumping), enriches each one against
  MITRE ATT&CK, scores its severity, and correlates related events into
  incidents — mirroring the ingest → enrich → score → correlate → sink
  pipeline a real SIEM runs.
- **MITRE ATT&CK mapping** (`backend/mitre_attack.py`): a local reference of
  ATT&CK tactics/techniques and the rules that map each event type onto
  the technique(s) it's characteristic of.
- **Severity scoring** (`backend/severity_engine.py`): a transparent 0–100
  model combining intrinsic event severity, asset criticality, sensor
  confidence, and a frequency bonus for repeated behavior.
- **Incident correlation**: events sharing a source IP + asset within a
  rolling time window are grouped into a single incident, so the frontend
  can render attack chains, not just a flat log.
- **REST API + WebSocket** (`backend/main.py`, FastAPI): historical queries
  (`/api/events`, `/api/incidents`, `/api/stats`, `/api/mitre-matrix`,
  `/api/timeline`) plus a `/ws/stream` WebSocket that fans out every
  enriched event and incident update live.
- **Frontend** (`frontend/`): a vanilla HTML/CSS/JS dashboard (Chart.js for
  the attack timeline and severity mix) — no build step required. Shows a
  live event feed with search/filter, a MITRE ATT&CK heat-matrix, and
  correlated incidents you can click into to see the full attack chain.

## Running it

```bash
cd backend
pip install -r requirements.txt
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

Then open **http://localhost:8000** — the backend serves the frontend
directly, so that's the only command you need. Events start streaming
immediately; refresh or watch live as attack campaigns unfold.

## Project layout

```
backend/
  main.py              FastAPI app: REST API, WebSocket, static serving
  stream_processor.py  Ingest -> enrich -> score -> correlate -> broadcast
  event_simulator.py   Synthetic SIEM log generator (noise + attack campaigns)
  mitre_attack.py       ATT&CK tactics/techniques + event->technique mapping
  severity_engine.py   0-100 severity scoring model
  database.py           SQLite persistence (events, incidents)
  models.py             Pydantic schemas
frontend/
  index.html
  style.css
  app.js                WebSocket client + Chart.js + DOM rendering
```

## Deploying: frontend on GitHub Pages + backend hosted elsewhere

GitHub Pages only serves static files, so it can host `frontend/` but not
the FastAPI/WebSocket backend. The split looks like this:

```
GitHub Pages  →  frontend/ (static HTML/CSS/JS)
Render/Fly/Railway/VPS  →  backend/ (FastAPI + WebSocket + SQLite)
```

### 1. Deploy the backend first, so you have a URL

Pick one of the options in the section below ("Deploying the backend") —
Render's free tier is the least friction. You'll end up with something
like `https://soc-dashboard-api.onrender.com`. CORS is already wide open
in `main.py` (`allow_origins=["*"]`) so it'll accept requests from your
`github.io` domain with no extra config.

### 2. Point the frontend at that backend

Edit `frontend/config.js`:

```js
window.SOC_API_BASE = "https://soc-dashboard-api.onrender.com";
```

That's the only code change needed — `app.js` already reads this value
for both its REST calls and its WebSocket connection (deriving
`wss://...` from `https://...` automatically).

### 3. Push the repo to GitHub

```bash
cd soc-dashboard
git init
git add .
git commit -m "SOC dashboard"
git branch -M main
git remote add origin https://github.com/<you>/<repo>.git
git push -u origin main
```

### 4. Turn on Pages, deployed via Actions

In the repo: **Settings → Pages → Source → GitHub Actions**. The included
workflow (`.github/workflows/deploy-pages.yml`) publishes the `frontend/`
folder automatically on every push to `main` — no manual build step. After
the first run completes (check the **Actions** tab), your dashboard is
live at `https://<you>.github.io/<repo>/`.

Push a change to anything under `frontend/` (e.g. edit `config.js` again
later) and it redeploys automatically.

### Note on free-tier backends going to sleep

Render's free tier spins the backend down after inactivity and takes
~30–60s to wake back up on the next request — the dashboard will just
show "reconnecting…" until it's up. Fine for a demo; upgrade to a paid
instance (or use Fly.io, which doesn't sleep on its free allowance) if you
want it always warm.

## Deploying the backend

The whole app is one process (FastAPI serves the API, the WebSocket, and
the static frontend together), so deployment is simple — but note the
**single-worker constraint**: the stream processor's incident/campaign
state and the list of connected WebSocket clients live in memory in that
one process, and SQLite assumes a single writer. Run exactly one instance
of this service; scale vertically (bigger machine), not horizontally,
unless you first move that state into Redis/Postgres.

### Option A — Docker (works anywhere)

```bash
docker compose up --build -d
```

This builds the image from the included `Dockerfile`, runs it on port
8000, and persists `soc.db` in a named volume (`soc-data`) so history
survives container restarts. Without compose:

```bash
docker build -t soc-dashboard .
docker run -d -p 8000:8000 -v soc-data:/app/backend/data soc-dashboard
```

### Option B — A PaaS with a Dockerfile (Render, Railway, Fly.io)

These are the least-friction path to a public URL with HTTPS handled for
you, and all three run a `Dockerfile` out of the box:

- **Render**: New → Web Service → point at your repo → it detects the
  `Dockerfile` → set instance count to 1 → deploy. Add a persistent disk
  mounted at `/app/backend/data` if you want event history to survive
  restarts (Settings → Disks).
- **Railway**: New Project → Deploy from repo → it detects the
  `Dockerfile` automatically. Add a volume mounted at
  `/app/backend/data` under the service's Volumes tab.
- **Fly.io**: `fly launch` in the project root (it'll find the
  `Dockerfile`), then `fly volumes create soc_data --size 1` and mount it
  at `/app/backend/data` in the generated `fly.toml`, then `fly deploy`.
  Fly proxies WebSockets by default, no extra config needed.

All three give you a `https://your-app.onrender.com`-style URL directly —
no separate reverse proxy or TLS setup required.

### Option C — A plain VPS (systemd + nginx)

```bash
# on the server
sudo apt install python3-venv nginx
git clone <your-repo> && cd soc-dashboard/backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

Create `/etc/systemd/system/soc-dashboard.service`:

```ini
[Unit]
Description=SOC Dashboard
After=network.target

[Service]
User=www-data
WorkingDirectory=/opt/soc-dashboard/backend
Environment="SOC_DB_PATH=/opt/soc-dashboard/backend/data/soc.db"
ExecStart=/opt/soc-dashboard/backend/venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000 --workers 1
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now soc-dashboard
```

Then put nginx in front for TLS and to proxy the WebSocket upgrade
(this is the part people usually miss — without the `Upgrade`/
`Connection` headers, the live feed silently falls back to nothing):

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

Run `sudo certbot --nginx -d your-domain.com` to add HTTPS.

### Before exposing this to the internet

- The API and WebSocket have no auth and CORS is wide open (`allow_origins=["*"]`)
  — fine for a local demo, not for a public deployment. Add an auth
  dependency to the routes in `main.py` and tighten `CORSMiddleware`
  before putting this on a public URL.
- The event simulator runs continuously and will grow `soc.db`
  indefinitely — add a retention job (delete events older than N days) if
  you leave this running long-term.

## Extending it toward a real deployment

- Swap `event_simulator.py` for a real Kafka/syslog consumer — the rest of
  the pipeline (`stream_processor.py`) already expects a `RawEvent` and
  doesn't care where it came from.
- Swap SQLite in `database.py` for Postgres/Timescale/Elasticsearch without
  touching the API layer.
- Replace the local ATT&CK table with the official STIX bundle
  (https://github.com/mitre/cti) for full technique coverage.
- Add auth (the API and WebSocket are open by default — fine for a local
  demo, not for anything internet-facing).
