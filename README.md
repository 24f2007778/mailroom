# Mailroom Action Gate

FastAPI service implementing the `ga5-mailroom-action-gate/v2` propose/commit API.
Both operations are sent as JSON `POST /` requests.

## Run

Install dependencies and start the service:

```powershell
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

Configure these environment variables in the hosting provider before accepting
propose requests:

| Variable | Purpose | Default |
| --- | --- | --- |
| `LLM_API_KEY` | API key for an OpenAI-compatible chat-completions provider. Required for uncached dossiers. | unset |
| `LLM_BASE_URL` | Provider API base URL. | `https://api.groq.com/openai/v1` |
| `LLM_MODEL` | Provider model identifier. | `openai/gpt-oss-120b` |
| `DATABASE_PATH` | SQLite database path. Mount durable storage at this path in hosted deployments. | `./mailroom_agent.db` |
| `LLM_BATCH_SIZE` | Maximum dossiers per model request (1–12). | `10` |
| `LLM_CONCURRENCY` | Maximum concurrent model requests. | `2` |
| `LLM_TIMEOUT_SECONDS` | Timeout for each provider request. | `35` |
| `PROPOSAL_TIMEOUT_SECONDS` | Overall limit for uncached proposal generation. | `48` |

The `LLM_API_KEY` must be supplied as a hosting secret; do not commit it or
include it in the submitted endpoint URL. Keep the SQLite database on persistent
storage so evaluation, receipt, and decision-cache state survives restarts.
Terminate HTTPS at the hosting provider's managed TLS proxy and expose the
service's root URL without query parameters or fragments.

`GET /` is a health check. The POST endpoint returns `503` for proposal
generation failures, including when `LLM_API_KEY` is unset.
