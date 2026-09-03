import tempfile
import os
import json
import time
import asyncio
import logging
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
import uvicorn
import structlog
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

from parser.modules import parse_directory
from parser.expansion import build_graph_with_expansion
from parser.references import resolve_resource_references
from parser.attachments import resolve_rule_attachments
from solver.engine import VerificationEngine

structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)
logger = structlog.get_logger("iac_verifier_webhook")

WEBHOOK_TIMEOUT_SECONDS = float(os.getenv("WEBHOOK_TIMEOUT_SECONDS", "8.0"))

REQUESTS_TOTAL = Counter(
    "iac_verifier_webhook_requests_total",
    "Total AdmissionReview requests processed by the webhook",
    ["outcome"]
)

SOLVER_TIMEOUT_TOTAL = Counter(
    "iac_verifier_webhook_solver_timeout_total",
    "Total solver timeout events encountered by the webhook"
)

REQUEST_DURATION_SECONDS = Histogram(
    "iac_verifier_webhook_request_duration_seconds",
    "Duration of AdmissionReview request processing in seconds",
    buckets=[0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 8.0, 10.0]
)

SOLVER_DURATION_SECONDS = Histogram(
    "iac_verifier_webhook_solver_duration_seconds",
    "Duration of SMT verification engine execution in seconds",
    buckets=[0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 8.0, 10.0]
)

app = FastAPI(title="IaC Verification Admission Webhook")


def _process_and_verify(data: dict, timeout_seconds: float) -> tuple[bool, str, float]:
    """
    Synchronous worker executed in a thread pool.
    Writes payload files to a temporary directory, parses, builds graph,
    and runs VerificationEngine with thread-safe per-instance Z3 solver timeout.
    Returns (is_allowed, message, solver_duration).
    """
    timeout_ms = int(timeout_seconds * 1000)

    with tempfile.TemporaryDirectory() as temp_dir:
        tf_files_found = False
        for filename, content in data.items():
            if isinstance(filename, str) and filename.endswith(".tf") and isinstance(content, str):
                tf_files_found = True
                file_path = os.path.join(temp_dir, filename)
                with open(file_path, "w") as f:
                    f.write(content)

        if not tf_files_found:
            return True, "No Terraform files found in payload; allowed.", 0.0

        parsed = parse_directory(temp_dir)
        graph = build_graph_with_expansion(parsed, temp_dir)
        graph = resolve_resource_references(graph)
        graph = resolve_rule_attachments(graph)

        engine = VerificationEngine(use_cache=False, timeout_ms=timeout_ms)
        solver_start = time.perf_counter()
        results = engine.verify_graph(graph, timeout_ms=timeout_ms)
        solver_duration = time.perf_counter() - solver_start

        SOLVER_DURATION_SECONDS.observe(solver_duration)

        is_safe = True
        is_timeout = False
        error_messages = []
        timeout_messages = []

        for res in results:
            if res.status == "TIMEOUT":
                is_safe = False
                is_timeout = True
                timeout_messages.append(f"[{res.pattern}] {res.resource_address}: {res.message}")
            elif res.status in ("SAT", "UNRESOLVABLE", "UNKNOWN"):
                is_safe = False
                msg = f"[{res.pattern}] {res.resource_address}: {res.message}"
                error_messages.append(msg)

        if is_timeout:
            detail = "\n".join(timeout_messages) if timeout_messages else f"Solver exceeded {timeout_seconds}s limit"
            return False, f"Verification timeout: solver execution exceeded timeout limit ({timeout_seconds}s) — failing closed.\nDetails: {detail}", solver_duration
        elif not is_safe:
            return False, "Verification failed. Vulnerabilities detected:\n" + "\n".join(error_messages), solver_duration
        else:
            return True, "Verification successful. All checks UNSAT.", solver_duration


@app.get("/metrics")
def get_metrics():
    """Prometheus metrics scraping endpoint."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/validate")
async def validate_resource(request: Request):
    """
    Kubernetes Validating Admission Webhook entrypoint.
    Expects an AdmissionReview v1 payload containing a ConfigMap with .tf files in the 'data' field.
    Enforces a strict internal timeout (default 8.0s) below K8s admission webhook 10s timeout.
    """
    start_time = time.perf_counter()
    payload = await request.json()

    # Extract the AdmissionReview request
    req = payload.get("request", {})
    uid = req.get("uid", "")

    # We expect a ConfigMap or a similar resource that contains TF code in a "data" field
    obj = req.get("object", {})
    kind = obj.get("kind", "")
    data = obj.get("data", {})

    # Fallback to 'spec' if 'data' is empty (e.g., custom CRD)
    if not data and "spec" in obj:
        data = obj["spec"]

    logger.info("admission_review_received", uid=uid, kind=kind)

    if not data or not any(isinstance(k, str) and k.endswith(".tf") for k in data.keys()):
        REQUESTS_TOTAL.labels(outcome="no_tf").inc()
        duration = time.perf_counter() - start_time
        REQUEST_DURATION_SECONDS.observe(duration)
        logger.info("admission_review_processed", uid=uid, allowed=True, outcome="NO_TF", duration_seconds=round(duration, 4))
        return build_admission_response(uid, True, "No Terraform files found in payload; allowed.")

    # Parse and verify offloaded to a worker thread with asyncio.wait_for timeout
    try:
        allowed, message, solver_duration = await asyncio.wait_for(
            asyncio.to_thread(_process_and_verify, data, WEBHOOK_TIMEOUT_SECONDS),
            timeout=WEBHOOK_TIMEOUT_SECONDS
        )
        duration = time.perf_counter() - start_time
        REQUEST_DURATION_SECONDS.observe(duration)

        if "Verification timeout:" in message:
            REQUESTS_TOTAL.labels(outcome="solver_timeout").inc()
            SOLVER_TIMEOUT_TOTAL.inc()
            logger.warning("admission_review_timeout", uid=uid, allowed=False, outcome="SOLVER_TIMEOUT", duration_seconds=round(duration, 4), solver_duration_seconds=round(solver_duration, 4), detail=message)
        elif allowed:
            REQUESTS_TOTAL.labels(outcome="allowed").inc()
            logger.info("admission_review_processed", uid=uid, allowed=True, outcome="ALLOWED", duration_seconds=round(duration, 4), solver_duration_seconds=round(solver_duration, 4))
        else:
            REQUESTS_TOTAL.labels(outcome="vulnerability_rejected").inc()
            logger.info("admission_review_processed", uid=uid, allowed=False, outcome="VULNERABILITY_REJECTED", duration_seconds=round(duration, 4), solver_duration_seconds=round(solver_duration, 4), detail=message)

        return build_admission_response(uid, allowed, message)

    except asyncio.TimeoutError:
        duration = time.perf_counter() - start_time
        REQUEST_DURATION_SECONDS.observe(duration)
        REQUESTS_TOTAL.labels(outcome="solver_timeout").inc()
        SOLVER_TIMEOUT_TOTAL.inc()
        msg = f"Verification timeout: solver execution exceeded timeout limit ({WEBHOOK_TIMEOUT_SECONDS}s) — failing closed"
        logger.warning("admission_review_timeout", uid=uid, allowed=False, outcome="SOLVER_TIMEOUT", duration_seconds=round(duration, 4), timeout_seconds=WEBHOOK_TIMEOUT_SECONDS, detail=msg)
        return build_admission_response(uid, False, msg)

    except Exception as e:
        duration = time.perf_counter() - start_time
        REQUEST_DURATION_SECONDS.observe(duration)
        REQUESTS_TOTAL.labels(outcome="error").inc()
        logger.error("admission_review_error", uid=uid, allowed=False, outcome="ERROR", duration_seconds=round(duration, 4), error=str(e))
        return build_admission_response(uid, False, f"Verification engine error: {str(e)}")


def build_admission_response(uid: str, allowed: bool, message: str) -> JSONResponse:
    """Constructs the standard AdmissionReview v1 response payload."""
    response = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "uid": uid,
            "allowed": allowed,
            "status": {
                "message": message
            }
        }
    }
    return JSONResponse(content=response)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8443)

