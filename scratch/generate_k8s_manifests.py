import base64
import os

with open("certs/ca.crt", "rb") as f:
    ca_bytes = f.read()

ca_b64 = base64.b64encode(ca_bytes).decode("utf-8")

os.makedirs("scratch/k8s", exist_ok=True)

webhook_config_yaml = f"""apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: iac-verifier-webhook
webhooks:
  - name: iac-verifier.default.svc
    rules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["configmaps"]
        scope: "Namespaced"
    clientConfig:
      service:
        name: iac-webhook-service
        namespace: default
        path: "/validate"
        port: 443
      caBundle: "{ca_b64}"
    admissionReviewVersions: ["v1"]
    sideEffects: None
    timeoutSeconds: 10
    failurePolicy: Fail
"""

with open("scratch/k8s/webhook-configuration.yaml", "w") as f:
    f.write(webhook_config_yaml)

unsafe_cm_yaml = """apiVersion: v1
kind: ConfigMap
metadata:
  name: unsafe-infrastructure
  namespace: default
data:
  main.tf: |
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

with open("scratch/k8s/unsafe-configmap.yaml", "w") as f:
    f.write(unsafe_cm_yaml)

safe_cm_yaml = """apiVersion: v1
kind: ConfigMap
metadata:
  name: safe-infrastructure
  namespace: default
data:
  main.tf: |
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

with open("scratch/k8s/safe-configmap.yaml", "w") as f:
    f.write(safe_cm_yaml)

print("Generated Kubernetes manifests in scratch/k8s/")
