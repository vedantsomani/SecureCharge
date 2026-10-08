"""Private lab CA generation only. Production should use an operated device PKI."""

from __future__ import annotations
from datetime import datetime, timedelta, timezone
import ipaddress
import os
from pathlib import Path
from .security import CP_RE


def create_lab_pki(out: str | Path, charger: str = "CP-01", hostname: str = "localhost") -> dict[str, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    if not CP_RE.fullmatch(charger):
        raise ValueError("invalid charger identity")
    path = Path(out)
    path.mkdir(parents=True, exist_ok=False)
    if os.name != "nt":
        path.chmod(0o700)
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SecureCharge PRIVATE LAB CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
        .sign(ca_key, hashes.SHA256())
    )

    def write(name, data):
        fd = os.open(path / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)

    def save_key(name, key):
        write(
            name,
            key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            ),
        )

    write("ca.pem", ca.public_bytes(serialization.Encoding.PEM))
    save_key("ca-key.pem", ca_key)
    for name, client in (("backend", False), ("gateway", True)):
        key = ec.generate_private_key(ec.SECP256R1())
        principal = charger if client else hostname
        san = (
            [x509.UniformResourceIdentifier("urn:securecharge:charger:" + charger)]
            if client
            else [x509.DNSName(hostname), x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
        )
        leaf = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, principal)]))
            .issuer_name(ca.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=7))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.SubjectAlternativeName(san), False)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH]),
                False,
            )
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, None, None), True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
            .sign(ca_key, hashes.SHA256())
        )
        write(name + ".pem", leaf.public_bytes(serialization.Encoding.PEM))
        save_key(name + "-key.pem", key)
    return {
        name: str(path / filename)
        for name, filename in {
            "ca": "ca.pem",
            "server_cert": "backend.pem",
            "server_key": "backend-key.pem",
            "client_cert": "gateway.pem",
            "client_key": "gateway-key.pem",
        }.items()
    }
