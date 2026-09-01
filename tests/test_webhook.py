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
