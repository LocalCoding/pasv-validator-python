import json
import os
import httpx

BACKEND_URLS = {
    "local": ["http://localhost:5000/validation/receive/result"],
    "prod": ["https://server-prod.pasv.us/validation/receive/result"],
}


async def send_result(
    *,
    user_id: str | None,
    challenge_id: str | None,
    results: list[dict],
    total_tests: int,
    passed_tests: int,
    solution: str,
) -> None:
    env = os.getenv("NODE_ENV", "prod")
    urls = BACKEND_URLS.get(env, BACKEND_URLS["prod"])

    payload = [
        json.dumps({
            "event": "start",
            "payload": {
                "userId": user_id,
                "challengeId": challenge_id,
                "solution": solution,
            },
        }),
        *[json.dumps(r) for r in results],
        json.dumps({
            "event": "end",
            "payload": {"tests": total_tests, "passes": passed_tests},
        }),
    ]

    async with httpx.AsyncClient(timeout=10.0) as client:
        for url in urls:
            try:
                await client.post(url, json=payload)
            except httpx.HTTPError as e:
                print(f"Callback to {url} failed: {e}", flush=True)
