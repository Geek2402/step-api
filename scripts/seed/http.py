import json
import urllib.error
import urllib.request


def request(
    method: str,
    url: str,
    body: dict | None = None,
    headers: dict | None = None,
) -> tuple[int, dict]:
    """Synchronous HTTP call to the running API. Returns (status_code, parsed_json_body).

    A 4xx/5xx response is NOT raised as an exception (unlike requests/httpx by default) —
    the caller decides what a given status code means for its own flow, since this script
    deliberately triggers plenty of expected error responses (401/403/404/409/429)."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)

    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {"detail": raw.decode("utf-8", errors="replace")}
        return exc.code, parsed


def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def app_token_header(token: str) -> dict:
    return {"X-App-Token": token}
