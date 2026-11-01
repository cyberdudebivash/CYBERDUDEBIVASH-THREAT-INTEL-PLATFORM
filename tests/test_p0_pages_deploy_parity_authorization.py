"""Offline release-contract tests: failed Pages parity must prevent gh-pages writes.

Regression: publisher #109 ran the Pages force-push action after the preceding
parity preflight returned exit 2. GitHub's explicit if: expression overrides
the implicit success() check unless the preflight is an explicit dependency.
No network, credentials, Pages deployment, or Cloudflare calls.
"""
import unittest
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/sentinel-apex.yml"

PREFLIGHT = "P0 predeploy Pages/report catalog parity (offline HARD FAIL)"
DEPLOY = "STAGE 5 - Deploy to GitHub Pages"
FRESHNESS = "STAGE 5.4.9.1 - GitHub Pages Deployment Freshness Gate (v184.1)"
PREFLIGHT_CHECK = "steps['p0-pages-parity-preflight'].outcome == 'success'"
DEPLOY_CHECK = "steps['p0-pages-deploy'].outcome == 'success'"


def step_block(workflow: str, name: str) -> str:
    marker = '      - name: "' + name + '"\n'
    if workflow.count(marker) != 1:
        raise AssertionError("Expected exactly one named release step: " + name)
    after = workflow.split(marker, 1)[1]
    return after.split("\n      - name:", 1)[0]


def assert_release_authorization(workflow: str) -> None:
    preflight = step_block(workflow, PREFLIGHT)
    deploy = step_block(workflow, DEPLOY)
    freshness = step_block(workflow, FRESHNESS)
    if not (workflow.index(PREFLIGHT) < workflow.index(DEPLOY) < workflow.index(FRESHNESS)):
        raise AssertionError("Release step ordering changed")
    if "id: p0-pages-parity-preflight" not in preflight:
        raise AssertionError("Missing explicit preflight step ID")
    if "run: python3 scripts/p0_pages_report_parity_preflight.py" not in preflight:
        raise AssertionError("Preflight execution removed")
    if "continue-on-error:" in preflight or "|| true" in preflight:
        raise AssertionError("Preflight no longer fails closed")
    if "id: p0-pages-deploy" not in deploy:
        raise AssertionError("Missing Pages deploy step ID")
    if "uses: JamesIves/github-pages-deploy-action@fa24774553152dd7873cd16ebd8d959b010c5445" not in deploy:
        raise AssertionError("Pages action pin changed")
    if PREFLIGHT_CHECK not in deploy:
        raise AssertionError("Pages deployment can bypass failed preflight")
    if PREFLIGHT_CHECK not in freshness or DEPLOY_CHECK not in freshness:
        raise AssertionError("Freshness probe can run without authorized deployment")


class TestPagesDeployParityAuthorization(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_parity_preflight_is_mandatory_for_deployment(self):
        assert_release_authorization(self.workflow)

    def test_missing_deploy_dependency_is_detected(self):
        deploy = step_block(self.workflow, DEPLOY)
        self.assertIn(PREFLIGHT_CHECK, deploy)
        broken = self.workflow.replace(
            deploy, deploy.replace(" && " + PREFLIGHT_CHECK, ""), 1
        )
        with self.assertRaisesRegex(AssertionError, "bypass failed preflight"):
            assert_release_authorization(broken)

    def test_missing_freshness_dependency_is_detected(self):
        freshness = step_block(self.workflow, FRESHNESS)
        self.assertIn(DEPLOY_CHECK, freshness)
        broken = self.workflow.replace(
            freshness, freshness.replace(" && " + DEPLOY_CHECK, ""), 1
        )
        with self.assertRaisesRegex(AssertionError, "without authorized deployment"):
            assert_release_authorization(broken)

    def test_continue_on_error_cannot_be_added_to_preflight(self):
        preflight = step_block(self.workflow, PREFLIGHT)
        broken = self.workflow.replace(
            preflight, preflight + "\n        continue-on-error: true", 1
        )
        with self.assertRaisesRegex(AssertionError, "fails closed"):
            assert_release_authorization(broken)


if __name__ == "__main__":
    unittest.main()
