import pytest
from fastapi.testclient import TestClient
from cli.webhook import app

client = TestClient(app)

def test_webhook_admit_safe_payload():
    safe_tf = """
    resource "aws_security_group" "safe_sg" {
        name = "safe-sg"
        ingress {
            from_port = 443
            to_port = 443
            protocol = "tcp"
            cidr_blocks = ["10.0.0.0/8"]
        }
    }
    """
    
    payload = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": "1234-safe-uid",
            "object": {
                "kind": "ConfigMap",
                "data": {
                    "main.tf": safe_tf
                }
            }
        }
    }
    
    response = client.post("/validate", json=payload)
    assert response.status_code == 200
    
    resp_data = response.json()
    assert resp_data["response"]["uid"] == "1234-safe-uid"
    assert resp_data["response"]["allowed"] is True
    assert "Verification successful" in resp_data["response"]["status"]["message"]


def test_webhook_reject_unsafe_payload():
    unsafe_tf = """
    resource "aws_security_group" "unsafe_sg" {
        name = "unsafe-sg"
        ingress {
            from_port = 22
            to_port = 22
            protocol = "tcp"
            cidr_blocks = ["0.0.0.0/0"]
        }
    }
    """
    
    payload = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": "5678-unsafe-uid",
            "object": {
                "kind": "ConfigMap",
                "data": {
                    "main.tf": unsafe_tf
                }
            }
        }
    }
    
    response = client.post("/validate", json=payload)
    assert response.status_code == 200
    
    resp_data = response.json()
    assert resp_data["response"]["uid"] == "5678-unsafe-uid"
    assert resp_data["response"]["allowed"] is False
    
    msg = resp_data["response"]["status"]["message"]
    assert "Verification failed" in msg
    assert "SG_OVER_EXPOSURE" in msg
    assert "aws_security_group.unsafe_sg" in msg


def test_webhook_timeout_asyncio_error(monkeypatch):
    """Verify that an asyncio.TimeoutError produces an explicit fail-closed response clearly distinguishable from vulnerability rejections."""
    import asyncio
    async def mock_wait_for(fut, timeout):
        if asyncio.iscoroutine(fut):
            fut.close()
        raise asyncio.TimeoutError()

    monkeypatch.setattr("asyncio.wait_for", mock_wait_for)

    payload = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": "timeout-uid-1",
            "object": {
                "kind": "ConfigMap",
                "data": {
                    "main.tf": "resource \"aws_security_group\" \"test\" {}"
                }
            }
        }
    }

    response = client.post("/validate", json=payload)
    assert response.status_code == 200

    resp_data = response.json()
    assert resp_data["response"]["uid"] == "timeout-uid-1"
    assert resp_data["response"]["allowed"] is False

    msg = resp_data["response"]["status"]["message"]
    assert "Verification timeout:" in msg
    assert "failing closed" in msg
    assert "Vulnerabilities detected" not in msg


def test_webhook_timeout_z3_solver(monkeypatch):
    """Verify that a Z3 solver TIMEOUT result produces a fail-closed response with explicit timeout details."""
    from solver.engine import VerificationResult

    def mock_verify_graph(self, graph, timeout_ms=None):
        return [
            VerificationResult(
                status="TIMEOUT",
                resource_address="aws_security_group.complex_sg",
                pattern="SG_OVER_EXPOSURE",
                message="Z3 solver timed out for security group 'aws_security_group.complex_sg'",
            )
        ]

    monkeypatch.setattr("solver.engine.VerificationEngine.verify_graph", mock_verify_graph)

    payload = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": "timeout-uid-2",
            "object": {
                "kind": "ConfigMap",
                "data": {
                    "main.tf": """
                    resource "aws_security_group" "complex_sg" {
                        name = "complex"
                    }
                    """
                }
            }
        }
    }

    response = client.post("/validate", json=payload)
    assert response.status_code == 200

    resp_data = response.json()
    assert resp_data["response"]["uid"] == "timeout-uid-2"
    assert resp_data["response"]["allowed"] is False

    msg = resp_data["response"]["status"]["message"]
    assert "Verification timeout:" in msg
    assert "failing closed" in msg
    assert "aws_security_group.complex_sg" in msg
    assert "Vulnerabilities detected" not in msg


def test_webhook_pathological_timeout(monkeypatch):
    """Verify end-to-end webhook behavior when configured with an ultra-short timeout (0.0001s)."""
    monkeypatch.setattr("cli.webhook.WEBHOOK_TIMEOUT_SECONDS", 0.0001)

    payload = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": "pathological-uid",
            "object": {
                "kind": "ConfigMap",
                "data": {
                    "main.tf": """
                    resource "aws_security_group" "sg" {
                        name = "sg"
                        ingress {
                            from_port = 80
                            to_port = 80
                            protocol = "tcp"
                            cidr_blocks = ["10.0.0.0/8"]
                        }
                    }
                    """
                }
            }
        }
    }

    response = client.post("/validate", json=payload)
    assert response.status_code == 200

    resp_data = response.json()
    assert resp_data["response"]["uid"] == "pathological-uid"
    assert resp_data["response"]["allowed"] is False

    msg = resp_data["response"]["status"]["message"]
    assert "Verification timeout:" in msg
    assert "failing closed" in msg

