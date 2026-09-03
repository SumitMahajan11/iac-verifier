import tempfile
import os
import json
import asyncio
import logging
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn

from parser.modules import parse_directory
from parser.expansion import build_graph_with_expansion
from parser.references import resolve_resource_references
from parser.attachments import resolve_rule_attachments
from solver.engine import VerificationEngine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

WEBHOOK_TIMEOUT_SECONDS = float(os.getenv("WEBHOOK_TIMEOUT_SECONDS", "8.0"))

app = FastAPI(title="IaC Verification Admission Webhook")

def _process_and_verify(data: dict, timeout_seconds: float) -> tuple[bool, str]:
    """
    Synchronous worker executed in a thread pool.
    Writes payload files to a temporary directory, parses, builds graph,
    and runs VerificationEngine with thread-safe per-instance Z3 solver timeout.
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
            return True, "No Terraform files found in payload; allowed."

        parsed = parse_directory(temp_dir)
        graph = build_graph_with_expansion(parsed, temp_dir)
        graph = resolve_resource_references(graph)
        graph = resolve_rule_attachments(graph)

        engine = VerificationEngine(use_cache=False, timeout_ms=timeout_ms)
        results = engine.verify_graph(graph, timeout_ms=timeout_ms)

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
            return False, f"Verification timeout: solver execution exceeded timeout limit ({timeout_seconds}s) — failing closed.\nDetails: {detail}"
        elif not is_safe:
            return False, "Verification failed. Vulnerabilities detected:\n" + "\n".join(error_messages)
        else:
            return True, "Verification successful. All checks UNSAT."


@app.post("/validate")
async def validate_resource(request: Request):
    """
    Kubernetes Validating Admission Webhook entrypoint.
    Expects an AdmissionReview v1 payload containing a ConfigMap with .tf files in the 'data' field.
    Enforces a strict internal timeout (default 8.0s) below K8s admission webhook 10s timeout.
    """
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

    logger.info(f"Received AdmissionReview UID: {uid} for Kind: {kind}")

    if not data or not any(isinstance(k, str) and k.endswith(".tf") for k in data.keys()):
        return build_admission_response(uid, True, "No Terraform files found in payload; allowed.")

    # Parse and verify offloaded to a worker thread with asyncio.wait_for timeout
    try:
        allowed, message = await asyncio.wait_for(
            asyncio.to_thread(_process_and_verify, data, WEBHOOK_TIMEOUT_SECONDS),
            timeout=WEBHOOK_TIMEOUT_SECONDS
        )
        return build_admission_response(uid, allowed, message)
    except asyncio.TimeoutError:
        logger.warning(f"AdmissionReview UID {uid} timed out after {WEBHOOK_TIMEOUT_SECONDS}s")
        return build_admission_response(
            uid,
            False,
            f"Verification timeout: solver execution exceeded timeout limit ({WEBHOOK_TIMEOUT_SECONDS}s) — failing closed"
        )
    except Exception as e:
        logger.error(f"Error processing AdmissionReview UID {uid}: {e}")
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
