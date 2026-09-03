import time
import json
from fastapi.testclient import TestClient
from cli.webhook import app, WEBHOOK_TIMEOUT_SECONDS

client = TestClient(app)

print(f"=== Webhook Default Timeout Configuration ===")
print(f"WEBHOOK_TIMEOUT_SECONDS = {WEBHOOK_TIMEOUT_SECONDS}")

# 1. Normal safe payload test
safe_tf = """
resource "aws_security_group" "safe_sg" {
    name = "safe"
    ingress {
        from_port = 443
        to_port = 443
        protocol = "tcp"
        cidr_blocks = ["10.0.0.0/8"]
    }
}
"""
payload_safe = {
    "apiVersion": "admission.k8s.io/v1",
    "kind": "AdmissionReview",
    "request": {
        "uid": "real-safe-uid",
        "object": {
            "kind": "ConfigMap",
            "data": {
                "main.tf": safe_tf
            }
        }
    }
}

t0 = time.perf_counter()
res_safe = client.post("/validate", json=payload_safe)
dt_safe = time.perf_counter() - t0
print(f"\n--- Safe Payload Response (Elapsed: {dt_safe:.3f}s) ---")
print(json.dumps(res_safe.json(), indent=2))

# 2. Pathological Z3 solver workload test with real low timeout limit (0.5s)
import cli.webhook
cli.webhook.WEBHOOK_TIMEOUT_SECONDS = 0.5

pathological_tf = """
resource "aws_security_group" "pathological_sg" {
    name = "pathological"
    ingress {
        from_port = 22
        to_port = 22
        protocol = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }
}
"""
payload_pathological = {
    "apiVersion": "admission.k8s.io/v1",
    "kind": "AdmissionReview",
    "request": {
        "uid": "real-pathological-uid",
        "object": {
            "kind": "ConfigMap",
            "data": {
                "main.tf": pathological_tf
            }
        }
    }
}

from solver.engine import VerificationEngine, VerificationResult
import z3

orig_verify_sg = VerificationEngine.verify_security_group

def pathological_verify_sg(self, resource, timeout_ms=None):
    # Construct a real complex non-linear SMT solver query to force Z3 solver execution
    solver = z3.Solver()
    eff_timeout = timeout_ms or self.timeout_ms
    if eff_timeout is not None:
        solver.set("timeout", eff_timeout)
    
    vars = [z3.Int(f"x_{i}") for i in range(100)]
    solver.add(z3.Sum([v * v * v for v in vars]) == 987654321)
    
    check_res = solver.check()
    if check_res == z3.unknown:
        reason = solver.reason_unknown()
        status = "TIMEOUT" if reason == "timeout" else "UNKNOWN"
        msg = f"Z3 solver timed out for security group '{resource.address}' after {eff_timeout}ms"
        return VerificationResult(
            status=status,
            resource_address=resource.address,
            pattern="SG_OVER_EXPOSURE",
            message=msg,
        )
    return orig_verify_sg(self, resource, timeout_ms)

VerificationEngine.verify_security_group = pathological_verify_sg

t0 = time.perf_counter()
res_pathological = client.post("/validate", json=payload_pathological)
dt_pathological = time.perf_counter() - t0
print(f"\n--- Pathological Solver Preemption Response (Configured Timeout: 0.5s, Elapsed: {dt_pathological:.3f}s) ---")
print(json.dumps(res_pathological.json(), indent=2))

# Restore timeout to 8.0s
cli.webhook.WEBHOOK_TIMEOUT_SECONDS = 8.0
print(f"\n=== Restored Timeout Configuration ===")
print(f"cli.webhook.WEBHOOK_TIMEOUT_SECONDS = {cli.webhook.WEBHOOK_TIMEOUT_SECONDS}")
