import asyncio
import os
import time

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .callback import send_result
from .equal_validator import validate_equal
from .runner import init_sandbox, run

init_sandbox()
app = FastAPI()
_started_at = time.time()


class ValidateRequest(BaseModel):
    solution: str | None = ""
    test: str | None = ""
    userId: str | None = None
    challengeId: str | None = None
    programmingLang: str | None = None


class EqualRequest(BaseModel):
    solution: str | None = ""
    completedSolution: str | None = ""


@app.get("/test")
async def healthcheck():
    return {"status": "ok", "uptime": time.time() - _started_at}


@app.post("/validate/unit/place")
async def validate_unit_place(body: ValidateRequest):
    if not body.solution and not body.test:
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": "Missing solution or test"},
        )

    if body.programmingLang and body.programmingLang != "Python":
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "message": f"Language {body.programmingLang} is not supported by python validator",
            },
        )

    try:
        result = await asyncio.to_thread(run, body.solution or "", body.test or "")
    except Exception as e:
        print(f"Validation error: {e}", flush=True)
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": "There is an issue with container creation."},
        )

    asyncio.create_task(
        _safe_callback(
            user_id=body.userId,
            challenge_id=body.challengeId,
            results=result["results"],
            total_tests=result["totalTests"],
            passed_tests=result["passedTests"],
            solution=body.solution or "",
        )
    )

    return {
        "success": True,
        "message": "Container has been created and result has been sent.",
        "payload": None,
    }


@app.post("/validate/equal")
async def validate_equal_endpoint(body: EqualRequest):
    warnings = validate_equal(body.solution, body.completedSolution)
    passed = warnings and warnings[0].get("type") == "passed"
    return {
        "success": True,
        "message": "Everything is good" if passed else "Warnings",
        "payload": warnings,
    }


async def _safe_callback(**kwargs):
    try:
        await send_result(**kwargs)
    except Exception as e:
        print(f"Callback error: {e}", flush=True)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "7001")))
