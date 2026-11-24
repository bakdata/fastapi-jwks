import datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


@pytest.fixture()
def ca_cert_path(tmp_path: Path) -> Path:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fastapi-jwks test CA")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    path = tmp_path / "ca.pem"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path
