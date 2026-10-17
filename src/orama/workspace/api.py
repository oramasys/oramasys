"""Authenticated local workspace endpoints; no content logging or persistence."""
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from orama.workspace.workflow import WorkspaceTask, capabilities, run_task

router = APIRouter()
MAX_BODY_BYTES = 262144


@router.get("/api/workspace/capabilities")
def workspace_capabilities():
    return JSONResponse(capabilities(), headers={"Cache-Control": "no-store"})


@router.post("/api/workspace/run")
async def workspace_run(request: Request):
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_BODY_BYTES:
            raise HTTPException(status_code=413, detail={"code": "workspace_input_too_large"})
    try:
        task = WorkspaceTask.model_validate_json(bytes(body))
        result = run_task(task)
    except ValidationError:
        raise HTTPException(status_code=422, detail={"code": "workspace_input_invalid"}) from None
    except ValueError:
        raise HTTPException(status_code=422, detail={"code": "workspace_verification_failed"}) from None
    return JSONResponse(result, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
