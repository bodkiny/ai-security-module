# AI Security Module (MVP)

## Run
```bash
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```

## Test
```bash
pytest -q
```

## Endpoint
POST `/api/v1/secure-chat`

Example body:
```json
{
  "user_id": "student-1",
  "prompt": "Explain SQL injection."
}
```

## Monitoring (built-in, lightweight)
- Dashboard: `GET /api/v1/monitoring`
- JSON summary: `GET /api/v1/monitoring/summary?hours=24&recent_limit=20`

Quick usage:
```bash
task docker-up
task monitor-dashboard
task monitor-summary
```
