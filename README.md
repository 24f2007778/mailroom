# Mailroom Action Gate

FastAPI service implementing the `ga5-mailroom-action-gate/v2` propose/commit API.
Both operations are sent as JSON `POST /v1/mailroom/actions` requests. `POST /`
is also available as an alias.

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
| `LLM_BATCH_SIZE` | Maximum dossiers per model request (1–12). | `2` |
| `LLM_CONCURRENCY` | Maximum concurrent model requests (shared across requests in one app process). | `1` |
| `LLM_TIMEOUT_SECONDS` | Timeout for each provider request. | `35` |
| `PROPOSAL_TIMEOUT_SECONDS` | Overall limit for uncached proposal generation. | `48` |

If the provider rejects a batch as too large (HTTP 413), the service
automatically splits it into smaller batches and retries those. Render logs
include `llm_batch_split` warnings when this happens. If one dossier by itself
exceeds the provider's request limit, use a provider/model that accepts larger
requests; the service logs `llm_provider_single_dossier_rejected`.
Provider rate limits (HTTP 429) are retried up to two times using the
`Retry-After` header when supplied, with short bounded waits. Reduce request
volume or wait for the provider quota to reset if the service reports
`llm_provider_rate_limit_retries_exhausted` or a cooldown longer than six
seconds.
Transient provider server errors (HTTP 500, 502, 503, or 504) are retried up to
two times with short bounded waits. If they persist, check the provider's
availability and the configured model/base URL; the service returns HTTP 503.

The `LLM_API_KEY` must be supplied as a hosting secret; do not commit it or
include it in the submitted endpoint URL. Keep the SQLite database on persistent
storage so evaluation, receipt, and decision-cache state survives restarts.
Terminate HTTPS at the hosting provider's managed TLS proxy and submit the
service URL with `/v1/mailroom/actions`, without credentials, query parameters,
or fragments.

`GET /` is a health check. When proposal generation fails, inspect the hosting
provider's application logs (Render: service → Logs) at the time of the Check.
The service logs safe diagnostic categories such as `llm_provider_auth_error`,
`llm_provider_http_error`, `llm_provider_timeout`, and
`proposal_generation_failed`; it does not log API keys or dossier contents.
The POST response also includes a short `detail` value that can be inspected
in the caller's Network response. A `503` can indicate model configuration,
provider, timeout, or output-validation problems.
