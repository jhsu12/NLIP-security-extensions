"""Interactive tool-guard demo: one page, one agent run at a time, watched live.

    python -m demo.web --stub    # offline: scripted agent, simulated judge, stub sign-in
    python -m demo.web --signin stub   # live model + d3 judge, demo-user sign-in (no Google)
    python -m demo.web           # live: Jetstream model, d3 judge, Google sign-in
                                 # (needs .env: OPENAI_*, VSR_API_KEY, GOOGLE_WEB_CLIENT_ID)

Then open http://127.0.0.1:8030. Pick a task, a scenario (benign or an attack) and a
guard setting; the page sends the request over NLIP with your sign-in token and shows
each check the guard runs (catalog, pre-tool, post-tool) as it happens, then AgentDojo's
verdict: was the task done, did the attack succeed.
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import fields
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from security_extensions.oauth_login import make_stub_token

from .results_view import OUTCOMES, ResultsBrowser
from .runs import RunManager, RunSpec, export

STATIC = Path(__file__).with_name("static")
STUB_USER = "emma.johnson@bluesparrowtech.com"


def create_app(*, offline: bool, signin: str | None = None) -> FastAPI:
    manager = RunManager(offline=offline, signin=signin)
    stub_signin = manager.signin == "stub"
    browser = ResultsBrowser(manager)
    app = FastAPI(title="Tool guard demo")
    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.middleware("http")
    async def revalidate_pages(request: Request, call_next):
        # Pages and scripts change between demo versions; make browsers check for a newer copy
        # (an unchanged file still comes back as a cheap 304).
        response = await call_next(request)
        if not request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-cache")
        return response

    def get_run(run_id: str):
        run = manager.runs.get(run_id)
        if run is None:
            raise HTTPException(404, "unknown or expired run")
        return run

    @app.get("/")
    async def index() -> FileResponse:
        return FileResponse(STATIC / "index.html")

    @app.get("/how")
    async def how() -> FileResponse:
        return FileResponse(STATIC / "how.html")

    @app.get("/runs")
    async def runs_page() -> FileResponse:
        return FileResponse(STATIC / "runs.html")

    # Saved evaluation episodes, browsed one by one (read-only; no keys needed).
    @app.get("/api/results")
    async def result_files() -> dict:
        return {"files": browser.files(), "outcomes": OUTCOMES}

    @app.get("/api/results/{name}")
    async def result_episodes(name: str) -> dict:
        try:
            return {"episodes": browser.episodes(name)}
        except KeyError as error:
            raise HTTPException(404, "unknown results file") from error

    @app.get("/api/results/{name}/events")
    async def result_events(name: str, key: str) -> dict:
        try:
            return {"events": browser.events(name, key)}
        except KeyError as error:
            raise HTTPException(404, "unknown results file or episode") from error

    @app.get("/checks")
    async def checks() -> FileResponse:
        return FileResponse(STATIC / "checks.html")

    @app.get("/api/options")
    async def options() -> dict:
        return {
            **manager.options(),
            "signin": {
                "provider": manager.signin,
                "web_client_id": None if stub_signin else os.getenv("GOOGLE_WEB_CLIENT_ID", ""),
                "stub_user": STUB_USER if stub_signin else None,
            },
        }

    if stub_signin:
        # Exists only with stub sign-in: mints the locally signed token oauth_verify accepts then.
        @app.post("/api/stub-login")
        async def stub_login(request: Request) -> dict:
            body = await request.json() if await request.body() else {}
            email = str(body.get("email") or STUB_USER)
            return {"token": make_stub_token(email), "email": email}

    def spec_from(body: dict) -> RunSpec:
        spec = RunSpec()
        for name in (f.name for f in fields(RunSpec) if f.name in body):
            if not body[name] and name in ("scenario", "guard"):
                continue  # keep the default
            # An explicit empty task_id means a free-text request, not the default task.
            setattr(spec, name, body[name] or None)
        return spec

    @app.post("/api/preview")
    async def preview(request: Request) -> dict:
        try:
            return manager.preview(spec_from(await request.json()))
        except (ValueError, KeyError) as error:
            raise HTTPException(400, str(error)) from error

    @app.post("/api/runs")
    async def create_run(request: Request) -> dict:
        try:
            run = await manager.create(spec_from(await request.json()))
        except (ValueError, KeyError) as error:
            raise HTTPException(400, str(error)) from error
        return {"run_id": run.id, "prompt": run.prompt}

    @app.post("/api/runs/{run_id}/nlip")
    async def send(run_id: str, request: Request) -> JSONResponse:
        status, body = await get_run(run_id).send(await request.json())
        return JSONResponse(body, status_code=status)

    @app.get("/api/runs/{run_id}/events")
    async def events(run_id: str, start: int = 0) -> StreamingResponse:
        run = get_run(run_id)

        async def stream():
            async for event in run.stream(start):
                yield ": keep-alive\n\n" if event is None else f"data: {json.dumps(event, default=str)}\n\n"

        return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})

    @app.get("/api/runs/{run_id}/export")
    async def export_run(run_id: str) -> Response:
        return Response(
            export(get_run(run_id)),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="tool-guard-run-{run_id}.json"'},
        )

    return app


def main() -> None:
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--stub", action="store_true", help="Offline mode (no network, no API keys)")
    parser.add_argument("--signin", choices=("google", "stub"),
                        help="Sign-in provider (default: google live, stub offline); stub needs no Google account")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8030)
    args = parser.parse_args()
    signin = args.signin or ("stub" if args.stub else "google")
    if signin == "google" and not os.getenv("GOOGLE_WEB_CLIENT_ID"):
        parser.error("Google sign-in needs GOOGLE_WEB_CLIENT_ID (see demo/README.md); or use --signin stub")

    import uvicorn

    uvicorn.run(create_app(offline=args.stub, signin=signin), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
