"""P0 offline dependency-floor regression for GHSA-xcq7-p3pf-p88h.

No network, installation, Cloudflare, billing, or customer-state operations.
Dependency resolution and pip-audit are independent mandatory CI gates.
"""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SERVICES = (
    "exec-risk", "ai-engine", "intel-core", "agentshield", "api-gateway",
    "surfacewatch", "intel-exchange", "soc-automation", "billing-engine",
)
PINNED = {
    "opentelemetry-sdk": "1.45.1",
    "opentelemetry-instrumentation-fastapi": "0.66b1",
    "opentelemetry-exporter-otlp-proto-grpc": "1.45.1",
}


def pins(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.split("#", 1)[0].strip()
        if text.startswith("opentelemetry-") and "==" in text:
            package, version = text.split("==", 1)
            result[package.strip()] = version.strip()
    return result


class OpenTelemetryPatchedPinsTests(unittest.TestCase):
    def test_core_and_all_nine_service_images_pin_patched_family(self):
        manifests = [ROOT / "requirements.txt"] + [
            ROOT / "platform" / "services" / name / "requirements.txt"
            for name in SERVICES
        ]
        for manifest in manifests:
            with self.subTest(manifest=str(manifest.relative_to(ROOT))):
                self.assertTrue(manifest.is_file())
                found = pins(manifest)
                for package, version in PINNED.items():
                    self.assertEqual(found.get(package), version)

    def test_core_requests_instrumentation_matches_patched_family(self):
        found = pins(ROOT / "requirements.txt")
        self.assertEqual(
            found.get("opentelemetry-instrumentation-requests"), "0.66b1"
        )

    def test_no_explicit_vulnerable_api_pin_in_active_manifests(self):
        manifests = [ROOT / "requirements.txt"] + [
            ROOT / "platform" / "services" / name / "requirements.txt"
            for name in SERVICES
        ]
        for manifest in manifests:
            with self.subTest(manifest=str(manifest.relative_to(ROOT))):
                self.assertNotIn(
                    "opentelemetry-api==1.44.0", manifest.read_text(encoding="utf-8")
                )


if __name__ == "__main__":
    unittest.main()
