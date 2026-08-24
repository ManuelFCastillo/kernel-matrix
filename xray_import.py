#!/usr/bin/env python3
"""
xray_import.py -- push JUnit results into Xray (Jira) as Test Executions.

WHY THIS IS A GOOD FIT
----------------------
The lab already emits JUnit XML per distro, because that is the universal
exchange format. Xray consumes JUnit natively, so no translation layer is
needed -- the same artifact that feeds Jenkins feeds test management.

The genuinely useful part is Xray's TEST ENVIRONMENTS. Each distro is
imported as a separate environment against the SAME test cases, so Xray
builds you a matrix view: one row per check, one column per kernel. That is
exactly the artifact a compatibility programme wants, and it is the thing a
CI console cannot give you because it has no memory across runs.

    km_kernel_version_matches   ubuntu-22.04  ubuntu-24.04  debian-12
                                    PASS          PASS         PASS
    km_btf_available                PASS          PASS         FAIL

SETUP YOU HAVE TO DO BY HAND (accounts, not code)
-------------------------------------------------
 1. A Jira Cloud site -- free for up to 10 users at atlassian.com
 2. Install "Xray Test Management" from the Atlassian Marketplace
    (30-day trial, paid after that)
 3. Create a Jira project and note its KEY, e.g. KM
 4. In Jira: Apps -> Xray -> API Keys -> create one.
    You get a Client ID and a Client Secret.

CREDENTIALS
-----------
Never put the secret in this file or on the command line (it lands in shell
history and in the Jenkins console). Use environment variables:

    export XRAY_CLIENT_ID=...
    export XRAY_CLIENT_SECRET=...
    export XRAY_PROJECT_KEY=KM

Or a .xray-credentials file next to this script, chmod 600, in KEY=value
form. It is gitignored.

USAGE
    ./xray_import.py                       # import every results/*.xml
    ./xray_import.py --dry-run             # show what would be sent
    ./xray_import.py --test-plan KM-12     # attach to an existing Test Plan
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

XRAY_BASE = "https://xray.cloud.getxray.app/api/v2"


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------
def load_credentials() -> tuple[str, str, str]:
    """
    Environment first, then a local file. Never a command-line argument --
    those end up in shell history and in CI logs.
    """
    cid = os.environ.get("XRAY_CLIENT_ID")
    secret = os.environ.get("XRAY_CLIENT_SECRET")
    project = os.environ.get("XRAY_PROJECT_KEY")

    cred_file = Path(__file__).parent / ".xray-credentials"
    if cred_file.exists() and not (cid and secret):
        for line in cred_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            value = value.strip().strip("'\"")
            key = key.strip().upper()
            if key == "XRAY_CLIENT_ID":
                cid = cid or value
            elif key == "XRAY_CLIENT_SECRET":
                secret = secret or value
            elif key == "XRAY_PROJECT_KEY":
                project = project or value

    missing = [n for n, v in
               [("XRAY_CLIENT_ID", cid), ("XRAY_CLIENT_SECRET", secret),
                ("XRAY_PROJECT_KEY", project)] if not v]
    if missing:
        sys.exit(
            "Missing credentials: " + ", ".join(missing) + "\n\n"
            "Set them in the environment, or create .xray-credentials next to\n"
            "this script (chmod 600) containing:\n\n"
            "    XRAY_CLIENT_ID=...\n"
            "    XRAY_CLIENT_SECRET=...\n"
            "    XRAY_PROJECT_KEY=KM\n\n"
            "Get the ID and secret from Jira: Apps -> Xray -> API Keys."
        )
    return cid, secret, project


def authenticate(client_id: str, client_secret: str) -> str:
    """
    Exchange the API key pair for a bearer token.

    The token is valid for 24 hours, which is far longer than any single
    import, so there is no need to cache or refresh it here.
    """
    body = json.dumps({"client_id": client_id, "client_secret": client_secret})
    req = urllib.request.Request(
        f"{XRAY_BASE}/authenticate", data=body.encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            # Xray returns the token as a JSON *string*, quotes included.
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode()[:200]
        sys.exit(f"Xray authentication failed ({exc.code}): {detail}\n"
                 "Check the client id and secret in Jira under Apps -> Xray -> API Keys.")


def import_junit(token: str, xml_path: Path, project_key: str,
                 environment: str, test_plan: str | None = None,
                 dry_run: bool = False) -> str | None:
    """
    Import one JUnit file as a Test Execution, tagged with a test environment.

    The environment is what makes the matrix view work: the same test cases
    get results recorded per kernel rather than overwriting each other.
    """
    params = {
        "projectKey": project_key,
        "testEnvironments": environment,
        # A stable summary so repeat runs group sensibly in Jira rather than
        # producing a wall of identically-named executions.
        "testExecutionSummary": f"Kernel matrix: {environment}",
    }
    if test_plan:
        params["testPlanKey"] = test_plan

    url = f"{XRAY_BASE}/import/execution/junit?" + urllib.parse.urlencode(params)

    if dry_run:
        print(f"  would POST {xml_path.name} ({xml_path.stat().st_size} bytes)")
        print(f"    -> {url}")
        return None

    req = urllib.request.Request(
        url, data=xml_path.read_bytes(),
        headers={"Content-Type": "text/xml",
                 "Authorization": f"Bearer {token}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read().decode())
            key = result.get("key") or (result.get("testExecIssue") or {}).get("key")
            return key
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode()[:300]
        print(f"  FAILED {xml_path.name}: HTTP {exc.code} {detail}", file=sys.stderr)
        return None


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results", type=Path, default=Path("results"))
    ap.add_argument("--test-plan", help="attach executions to an existing Test Plan, e.g. KM-12")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    xml_files = sorted(p for p in args.results.glob("*.xml"))
    if not xml_files:
        sys.exit(f"No JUnit XML in {args.results}. Run provision.py first.")

    client_id, client_secret, project_key = load_credentials()

    token = "DRY-RUN" if args.dry_run else authenticate(client_id, client_secret)
    if not args.dry_run:
        print(f"authenticated to Xray, project {project_key}")

    print(f"importing {len(xml_files)} result file(s):")
    created = []
    for xml in xml_files:
        # The filename is the distro, which becomes the Xray test environment.
        environment = xml.stem
        key = import_junit(token, xml, project_key, environment,
                           args.test_plan, args.dry_run)
        if key:
            print(f"  {environment:<18} -> {key}")
            created.append(key)
        elif not args.dry_run:
            print(f"  {environment:<18} -> no key returned")

    if created:
        print(f"\ncreated {len(created)} Test Execution(s): {', '.join(created)}")
        print("View the matrix in Jira: Xray -> Test Executions, "
              "or open the Test Plan to see results per environment.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
