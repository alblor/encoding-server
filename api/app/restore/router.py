"""HTTP routes of the restoration API, all under /v1/restore.

The service is read from request.app.state.restore_service, which main.py sets up in the lifespan
(tests set it by hand, as test_basic_functionality does for the other services).

Author: Lorenzo Albanese (alblor)
"""

import asyncio
import json
import time
from typing import Any, Callable, Optional

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.routing import APIRoute

from .models import api_error, get_principal
from .service import MAX_RECIPE_BYTES, RestoreService

MAX_COUNTER = 2**40


def get_service(request: Request) -> RestoreService:
    service = getattr(request.app.state, "restore_service", None)
    if service is None:
        raise api_error(
            503, "Restoration service is not initialised", "unavailable_error"
        )
    return service


def _bound_upload_time(request: Request, service: RestoreService, declared: int) -> None:
    """Gives the body read an idle timeout and a minimum average rate, so a stalled or dripping client frees its slot.

    The slot is reserved before the body arrives (that is what makes concurrent submits safe), and nothing else
    would ever end a connection that stops sending: a handful of them would hold every slot and every promised byte
    of the RAM volume. After a grace period the bytes received so far must keep up with the minimum rate, so a drip of one
    byte every 20 s is cut at the first check past the grace, whatever length it declared (the length is the client's word).
    """
    cfg = service.config
    started = time.monotonic()
    received = 0
    original = request._receive

    async def receive():
        nonlocal received
        try:
            message = await asyncio.wait_for(original(), timeout=cfg.upload_idle_seconds)
        except asyncio.TimeoutError:
            raise api_error(408, "The upload stalled", "request_timeout") from None
        received += len(message.get("body", b"")) if message.get("type") == "http.request" else 0
        elapsed = time.monotonic() - started
        if elapsed > cfg.upload_grace_seconds and received < cfg.upload_min_bytes_per_second * (elapsed - cfg.upload_grace_seconds):
            raise api_error(408, "The upload is too slow", "request_timeout")
        return message

    request._receive = receive


class _UploadGuardRoute(APIRoute):
    """Checks Content-Length before the framework reads (and spools) the multipart body.

    Starlette writes a multipart upload to a temporary file before the handler runs, with no
    size limit of its own, so the cap has to be enforced here, on the header. Chunked bodies have
    no length to check and are refused.
    """

    def get_route_handler(self) -> Callable:
        original = super().get_route_handler()

        async def guarded(request: Request):
            service = get_service(request)
            declared = request.headers.get("content-length")
            if declared is None:
                raise api_error(
                    411, "Content-Length is required for uploads", "validation_error"
                )
            if not declared.isdigit():
                raise api_error(400, "Invalid Content-Length", "validation_error")
            token = service.reserve_upload(int(declared))
            request.state.restore_reservation = token
            _bound_upload_time(request, service, int(declared))
            try:
                return await original(request)
            finally:
                service.release_upload(token)

        return guarded


router = APIRouter(prefix="/v1/restore", tags=["restore"])


@router.get("/presets")
def list_presets(service: RestoreService = Depends(get_service)):
    """Preset names with their descriptions and the recipe each one resolves to."""
    return {"presets": service.presets()}


@router.post("/recipe/resolve")
async def resolve_recipe(
    request: Request, service: RestoreService = Depends(get_service)
):
    """Validate a RecipeRequest and return the EffectiveRecipe. Nothing is queued.

    The body is read by hand, with a cap, so a huge or deeply nested document is refused
    before it is parsed.
    """
    too_big = api_error(
        413,
        f"The recipe is larger than {MAX_RECIPE_BYTES} bytes",
        "payload_too_large",
    )
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_RECIPE_BYTES:
        raise too_big
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_RECIPE_BYTES:
            raise too_big
    try:
        payload: Any = json.loads(bytes(body))
    except (ValueError, RecursionError):
        raise api_error(
            400,
            "The body is not valid JSON (or is nested too deeply)",
            "validation_error",
        ) from None
    return {
        "effective_recipe": json.loads(
            service.resolve_recipe(payload).model_dump_json()
        )
    }


async def submit_job(
    request: Request,
    file: UploadFile = File(...),
    recipe: str = Form(...),
    first_frame: int = Form(0, ge=0, le=MAX_COUNTER),
    segment_index: int = Form(0, ge=0, le=MAX_COUNTER),
    decryption_password: Optional[str] = Form(None),
    principal: str = Depends(get_principal),
    service: RestoreService = Depends(get_service),
):
    """Validate and queue one segment."""
    return await service.submit_job(
        principal,
        file,
        recipe,
        first_frame,
        segment_index,
        decryption_password,
        reservation=getattr(request.state, "restore_reservation", None),
    )


router.add_api_route(
    "/jobs", submit_job, methods=["POST"], route_class_override=_UploadGuardRoute
)


@router.get("/jobs/{job_id}")
def job_status(
    job_id: str,
    principal: str = Depends(get_principal),
    service: RestoreService = Depends(get_service),
):
    """Status, stage, progress, error and, when done, the size of the result."""
    return service.get_status(principal, job_id)


@router.get("/jobs/{job_id}/download")
def download(
    job_id: str,
    principal: str = Depends(get_principal),
    service: RestoreService = Depends(get_service),
):
    """Stream the result of a finished job, encrypted as the job's mode says."""
    handle = service.open_result(principal, job_id)
    return StreamingResponse(
        handle.stream,
        media_type=handle.media_type,
        headers={
            "Content-Length": str(handle.size),
            "Content-Disposition": f'attachment; filename="{handle.filename}"',
            "Cache-Control": "no-store",
        },
    )


@router.post("/jobs/{job_id}/cancel")
def cancel(
    job_id: str,
    principal: str = Depends(get_principal),
    service: RestoreService = Depends(get_service),
):
    """Stop a queued or running job. Calling it again is harmless."""
    return service.cancel(principal, job_id)


@router.delete("/jobs/{job_id}")
def delete(
    job_id: str,
    principal: str = Depends(get_principal),
    service: RestoreService = Depends(get_service),
):
    """Wipe the job's files and keys."""
    result = service.delete(principal, job_id)
    return JSONResponse(result, status_code=200 if result["deleted"] else 202)


@router.get("/capabilities")
def capabilities(service: RestoreService = Depends(get_service)):
    """Engines the attached workers offer, the queue length and the workers seen in the last minute."""
    return service.capabilities()


async def restore_validation_handler(request: Request, exc: RequestValidationError):
    """Answer request validation errors on /v1/restore in the project's error shape.

    The offending input is never echoed back (a form field can hold a password).
    """
    problems = []
    for err in exc.errors():
        loc = list(err.get("loc", ()))
        if loc and loc[0] in ("body", "query", "path", "header", "cookie"):
            loc = loc[1:]
        problems.append(
            {"field": ".".join(str(p) for p in loc), "message": str(err.get("msg", ""))}
        )
    message = "Invalid request: " + "; ".join(
        f"{p['field']}: {p['message']}" for p in problems
    )
    return JSONResponse(
        status_code=422,
        content={
            "detail": {
                "error": {
                    "message": message,
                    "type": "validation_error",
                    "problems": problems,
                }
            }
        },
    )
