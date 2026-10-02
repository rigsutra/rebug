# apitest

Point it at a Swagger/OpenAPI URL and it tests the API end to end. The backend
language doesn't matter (.NET, Express, anything): everything goes through the
spec and HTTP.

| Stage | Tool | What it catches |
|---|---|---|
| `lint` | Spectral (via `npx`) | Spec quality: missing schemas, missing descriptions, bad refs |
| `conformance` | Schemathesis | Type safety + fuzzing: responses that violate the schema, 500s, undocumented status codes, accepting invalid input, auth not enforced |
| `types` | built in | Wrong-type probing: every request-body field (nested too) gets values of other types, including look-alikes lenient parsers accept (`"1"` for an integer, `"true"`/`1`/`0` for a boolean, `"1.5"` for a number, `null` for non-nullable). Reports which field accepted which type |
| `authz` | built in | Secured endpoints served without / with junk credentials, **BOLA** (user B reading user A's data), stack-trace leaks, missing security headers, wildcard CORS with credentials |
| `zap` | OWASP ZAP API scan (Docker) | DAST: injection, header and misconfiguration issues |

Stages that can't run (no Node, no Docker) are reported as `skipped`. They never pass silently.

## Setup

```
python -m venv .venv
.venv\Scripts\pip install -e .
```

Optional: Node.js for `lint`, and Docker Desktop running for `zap`.

## Web UI

```
apitest ui
```

Then open http://localhost:8787.

**Projects.** One project = one API application: its Swagger document, base URL, test users,
BOLA scenarios and which tests to run. The home page lists all projects with their last result,
and each card has **Run all APIs** and **Stop** buttons.

**New project → Discover.** Enter the running app's URL (the root, the Swagger UI page, or the
spec JSON). apitest finds the Swagger/OpenAPI document(s) and lists every API before you save.
For a root URL it probes the usual locations: `/swagger/v1/swagger.json` (ASP.NET Core),
`/openapi/v1.json` (.NET 9), `/api-docs` (swagger-ui-express, including specs embedded in the page),
`/openapi.json`, `/v3/api-docs` and more. The same works on the CLI:

```
apitest discover https://orders-staging.example.com
```

**Inside a project:**
- **APIs** tab: every operation grouped by tag, with its **last result** (click it to see that API's
  findings). Tick APIs and press **Run selected**, or use **▶ Run** on a single row.
  **Refresh APIs** reloads the Swagger after the app changes.
- **Runs** tab: history. **Settings** tab: everything from the new-project form.
- **Export CLI config** gives the YAML for CI. Selecting APIs works there too: `apitest run --config x.yaml --op "GET /orders/{id}"`.

**Stop.** A running test can be stopped from the run page, the project page or the project card.
The current tool is killed (including its child processes, and the ZAP container) and partial
results from the stages that finished are kept.

**Tokens.** A header line like `Authorization: Bearer ${ORDERS_TOKEN_A}` is saved with the project,
and the variable is read from the apitest server's environment when a run starts. The CLI
supports `${VAR}` too. A literal token is held in server memory only, never written to disk, and
must be re-entered after the server restarts. Run files show header values as `***`.

- Data lives in `reports/projects/` and `reports/runs/<id>/` (change this with `--data-dir`).
- The UI binds to `127.0.0.1` by default. It sends requests to any URL you give it, so don't
  expose it on a shared network (`--host 0.0.0.0`) without authentication in front.

## Wrong-type probing (`types`)

For each POST/PUT/PATCH with a JSON body, apitest first sends a **valid baseline** body (the spec's
`example`, else one generated from the schema). Only if that returns 2xx does it swap each field to
each wrong type. Otherwise a rejection could be for any reason, and the operation is reported as
"skipped: baseline rejected". To fix that, add a working `example` to the request body (real IDs that
exist on staging).

Schemathesis (`conformance`) also sends wrong types, but it reports them as one generic
"accepted schema-violating request" per endpoint and doesn't send look-alike values. `types` names
the exact field and type.

## Run (CLI)

Quick, from flags only:

```
apitest run https://staging.example.com/swagger/v1/swagger.json -H "Authorization: Bearer <token>"
```

With a config file (recommended; see `examples/demo.yaml`):

```
apitest run --config myapi.yaml
```

Useful flags: `--base-url` (when the spec has no usable server/host), `--stages lint,conformance`,
`--max-examples 100`, `--fail-on medium`, `--no-mutating-authz`, `--out reports/myapi`.

Output goes to `reports/` by default: `report.html`, `report.json`, plus each tool's raw output
(`schemathesis-junit.xml`, `schemathesis.log`, `zap.html`, ...). The exit code is 1 if any finding is at or
above `fail_on` (default `high`) or a stage errored, so it can gate CI.

## BOLA tests

Scanners can't know who owns what, so you list a few resources owned by user A:

```yaml
headers:   {Authorization: Bearer <user A token>}
headers_b: {Authorization: Bearer <user B token>}
bola:
  - method: GET
    path: /api/orders/{id}
    params: {id: 1234}       # an order that belongs to user A
```

The tester checks that A gets 2xx, then replays as B and flags any 2xx.

## Writing specs that test well

- [docs/SWAGGER_GUIDE.md](docs/SWAGGER_GUIDE.md): the full guide for developers (what to put in the
  spec and why, ASP.NET Core and Express setup, checklist, finding → fix table).
- [docs/AI_RULES_OPENAPI.md](docs/AI_RULES_OPENAPI.md): a short rules block to paste into
  `CLAUDE.md` / Copilot / Cursor instructions in each API repo.

## Getting good results from .NET / Express specs

- **.NET (Swashbuckle/NSwag):** add `[ProducesResponseType]` for every status the action returns,
  enable nullable reference types, and declare the security scheme plus `AddSecurityRequirement`.
  Otherwise `authz` can't tell which endpoints are meant to be protected.
- **Express (swagger-jsdoc etc.):** make sure `security:` is declared and that response schemas exist.
  A hand-written spec drifts quickly, which is exactly what `conformance` will report.
- If the spec uses a relative server URL like `/api`, pass `--base-url`.

## Safety

Run against **staging**, never production. Fuzzing and ZAP active scanning send thousands of
requests, including POST/PUT/DELETE with garbage data. Use test accounts for the tokens.

## Demo

`examples/demo_api.py` is a small API with planted flaws:

```
uvicorn examples.demo_api:app --port 8000
apitest run --config examples/demo.yaml
```

## Tests

```
pytest tests
```
