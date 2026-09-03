import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import ipaddress
import base64
import os

os.makedirs("certs", exist_ok=True)

# 1. Generate CA key & certificate
ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ca_subject = ca_issuer = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "IaC Webhook CA"),
])
ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_subject)
    .issuer_name(ca_issuer)
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(ca_key, hashes.SHA256())
)

ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
with open("certs/ca.crt", "wb") as f:
    f.write(ca_pem)

# 2. Generate Server key & certificate
server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
server_subject = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "iac-webhook-service.default.svc"),
])

alt_names = [
    x509.DNSName("iac-webhook-service"),
    x509.DNSName("iac-webhook-service.default"),
    x509.DNSName("iac-webhook-service.default.svc"),
    x509.DNSName("iac-webhook-service.default.svc.cluster.local"),
]

server_cert = (
    x509.CertificateBuilder()
    .subject_name(server_subject)
    .issuer_name(ca_subject)
    .public_key(server_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
    .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
    .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    .sign(ca_key, hashes.SHA256())
)

with open("certs/server.crt", "wb") as f:
    f.write(server_cert.public_bytes(serialization.Encoding.PEM))

with open("certs/server.key", "wb") as f:
    f.write(server_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

ca_b64 = base64.b64encode(ca_pem).decode("utf-8")
print(f"CA Bundle Base64 generated successfully.")
