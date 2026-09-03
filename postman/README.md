# Postman

Two files:

| File | Purpose |
|---|---|
| `JussiAI-Web-Security-Scanner.postman_collection.json` | 33 requests across 5 folders |
| `JussiAI-Local.postman_environment.json` | `baseUrl` + `targetUrl` for local runs |

## Import

Postman → **Import** → drop both files in → select the **JussiAI - Local**
environment from the top-right picker.

## Variables

| Variable | Default | Notes |
|---|---|---|
| `baseUrl` | `http://127.0.0.1:8000` | Where the API is listening |
| `targetUrl` | `example.com` | The host to validate |

`targetUrl` intentionally defaults to `example.com`, the IANA-reserved
documentation domain. **No real target host is committed to this repo.** Point it
at a host you own, or are explicitly authorised to test, by editing the
environment locally — not the collection file.

## Run

```bash
.venv/bin/uvicorn jussiai_scanner.api.app:app --reload
```

Then **Run collection** in Postman, or headless with Newman:

```bash
npx newman run postman/JussiAI-Web-Security-Scanner.postman_collection.json \
  -e postman/JussiAI-Local.postman_environment.json
```

## Folders

- **Health** — `/health` and `/openapi.json`.
- **Scan** — `POST /scan`. Asserts that findings come back, that every one of
  them carries a `description` and a non-empty `remediation`, and that the
  severity counts add up. Non-info findings and their fixes are printed to the
  Postman console. **These make real outbound requests to `targetUrl`** — only
  scan hosts you own or are authorised to test. The folder also covers blocked
  and unreachable targets.
- **Validate - accepted** — targets that pass; expect `200`.
- **Validate - blocked (SSRF)** — 14 SSRF regression cases: loopback (plain,
  IPv6, IPv4-mapped, 6to4, NAT64), `localhost`, internal suffixes, cloud
  metadata (IPv4 and IPv6), RFC1918, CGNAT, `0.0.0.0`, and credential-masked
  hosts. **Every one must return `422`** — a `200` here means the SSRF
  protection has regressed.
- **Validate - malformed input** — bad schemes, disallowed ports, CRLF
  injection, numeric TLDs, and payloads the request model rejects. Expect `422`.

## `/scan` vs `/validate`

- `POST /scan` makes real read-only `GET` requests to the target and returns
  findings with remediation steps.
- `POST /validate` sends **nothing** to the target. It only answers whether the
  URL is allowed to be scanned.

Neither returns a score — the scoring algorithm is not implemented yet.
