import tempfile
import os
import json
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn
import logging

from parser.modules import parse_directory
from parser.expansion import build_graph_with_expansion
from parser.references import resolve_resource_references
from parser.attachments import resolve_rule_attachments
from solver.engine import VerificationEngine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="IaC Verification Admission Webhook")

@app.post("/validate")
async def validate_resource(request: Request):
    """
    Kubernetes Validating Admission Webhook entrypoint.
    Expects an AdmissionReview v1 payload containing a ConfigMap with .tf files in the 'data' field.
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

    with tempfile.TemporaryDirectory() as temp_dir:
        # 1. Write the extracted infrastructure code to the temp directory
        tf_files_found = False
        for filename, content in data.items():
            if filename.endswith(".tf"):
                tf_files_found = True
                file_path = os.path.join(temp_dir, filename)
                with open(file_path, "w") as f:
                    f.write(content)
                    
        if not tf_files_found:
            # If no TF files are found in the payload, allow it (not our concern)
            return build_admission_response(uid, True, "No Terraform files found in payload; allowed.")

        # 2. Parse and build the graph
        try:
            parsed = parse_directory(temp_dir)
            graph = build_graph_with_expansion(parsed, temp_dir)
            graph = resolve_resource_references(graph)
            graph = resolve_rule_attachments(graph)
        except Exception as e:
            return build_admission_response(uid, False, f"Failed to parse or build graph: {str(e)}")
            
        # 3. Verify the graph
        engine = VerificationEngine(use_cache=False)
        try:
            results = engine.verify_graph(graph)
        except Exception as e:
            return build_admission_response(uid, False, f"Verification engine error: {str(e)}")
            
        # 4. Evaluate results
        is_safe = True
        error_messages = []
        for res in results:
            if res.status in ("SAT", "UNRESOLVABLE", "UNKNOWN"):
                is_safe = False
                msg = f"[{res.pattern}] {res.resource_address}: {res.message}"
                error_messages.append(msg)
                
        if is_safe:
            return build_admission_response(uid, True, "Verification successful. All checks UNSAT.")
        else:
            return build_admission_response(uid, False, "Verification failed. Vulnerabilities detected:\n" + "\n".join(error_messages))


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
