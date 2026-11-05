"""Verify immutable mobile wire fixtures against Python JSON and cryptography.

This verifies serialization/signature interoperability only. Negative schema and
lease cases remain inputs for backend/Kotlin behavioral tests, not claimed passes.
"""
import base64
import hashlib
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "backend"))
from apps.reports.canonical import canonical  # noqa: E402
from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, utils  # noqa: E402


def decode(text):
    assert "=" not in text
    result = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    assert base64.urlsafe_b64encode(result).rstrip(b"=").decode("ascii") == text
    return result


def rejected(key, signature, message):
    try:
        key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        return
    raise AssertionError("Tampered proof unexpectedly verified")


def main():
    directory = Path(__file__).resolve().parent
    content = json.loads((directory / "mobile-canonical.json").read_text(encoding="utf-8"))
    vectors = {entry["id"]: entry for entry in content["vectors"]}
    for vector in vectors.values():
        result = canonical({"route": content["logical_route"], "body": vector["body"]})
        assert result.decode("utf-8") == vector["canonical_utf8"], vector["id"]
        assert result.hex() == vector["canonical_utf8_hex"], vector["id"]
        assert hashlib.sha256(result).hexdigest() == vector["sha256"], vector["id"]
    for form in content["equivalent_wire_forms"]:
        result = canonical({"route": content["logical_route"], "body": json.loads(form["raw_json"])})
        assert hashlib.sha256(result).hexdigest() == vectors[form["vector_id"]]["sha256"]
    assert vectors["unicode_nfc"]["sha256"] != vectors["unicode_decomposed"]["sha256"]
    assert vectors["baseline"]["sha256"] != vectors["timestamp_offset"]["sha256"]

    proof = json.loads((directory / "mobile-proof.json").read_text(encoding="utf-8"))
    spki = decode(proof["public_key_spki_base64url"])
    assert hashlib.sha256(spki).hexdigest() == proof["public_key_sha256"]
    key = serialization.load_der_public_key(spki)
    assert isinstance(key, ec.EllipticCurvePublicKey)
    assert isinstance(key.curve, ec.SECP256R1)
    assert key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == spki
    for vector in proof["vectors"]:
        binding = vector["binding"]
        message = "\n".join([
            "KAPIT-C2-MOBILE-PROOF-V1", binding["action"], binding["challenge_id"],
            binding["user_id"], binding["organization_id"], binding["enrollment_id"] or "-",
            binding["installation_id"], binding["key_fingerprint"], binding["nonce"],
            str(binding["expires_unix"]),
        ]) + "\n"
        assert message == vector["proof_message"]
        assert message.encode("utf-8").hex() == vector["proof_utf8_hex"]
        assert binding["key_fingerprint"] == proof["public_key_sha256"]
        assert len(decode(binding["nonce"])) == 32
        key.verify(decode(vector["signature_der_base64url"]), message.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    original = proof["vectors"][0]
    signature = decode(original["signature_der_base64url"])
    for case in proof["tamper_cases"]:
        altered = original["proof_message"]
        if "replace_line" in case:
            lines = altered.split("\n")
            lines[case["replace_line"]] = case["replacement"]
            altered = "\n".join(lines)
        elif case.get("remove_final_lf"):
            altered = altered[:-1]
        elif case.get("replace_lf_with_crlf"):
            altered = altered.replace("\n", "\r\n")
        assert altered != original["proof_message"]
        rejected(key, signature, altered.encode("utf-8"))
    r, s = utils.decode_dss_signature(signature)
    rejected(key, r.to_bytes(32, "big") + s.to_bytes(32, "big"), original["proof_message"].encode("utf-8"))
    rejected(key, signature + b"\x00", original["proof_message"].encode("utf-8"))
    print(json.dumps({
        "canonical_vectors_passed": len(vectors),
        "equivalent_wire_forms_passed": len(content["equivalent_wire_forms"]),
        "proof_vectors_passed": len(proof["vectors"]),
        "proof_tamper_rejections_passed": len(proof["tamper_cases"]) + 2,
        "negative_schema_cases": "not executed; contract inputs only",
        "lease_cases": "not executed; contract inputs only",
        "android_hardware": "not tested",
    }, indent=2))


if __name__ == "__main__":
    main()
