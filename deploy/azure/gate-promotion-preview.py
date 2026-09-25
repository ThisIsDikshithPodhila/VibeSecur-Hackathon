#!/usr/bin/env python3
"""Build-only preview of the independently verified payment patch on the VM."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from vibesecur.repair import prepare_candidate


BASE = "25ef1da2694f482bfc98e7ee7df0f7f0c714c8f0"
BASE_IMAGE = "sha256:01910ba6d1a5dc0a8fac9b62a8985ca24651098fb597b8074277c4888da22f91"
PATCH = Path("/srv/vibesecur/data/artifacts/dc56fa6f46034395a203d510179ca7ad/patch.diff")
EXPECTED_SOURCE = "117259a70c41a35b05e6d0f6e99ca53ac464a1b047be00d71f289cb06f353462"


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="preview-", dir="/srv/vibesecur/data") as scratch:
        root = Path(scratch)
        candidate = prepare_candidate("/srv/vibesecur/app", BASE, root / "candidate", PATCH.read_text())
        context = root / "context"
        shutil.copytree(candidate / "payment_app", context / "payment_app")
        base_tag = "vibesecur-payment-base:" + BASE_IMAGE.removeprefix("sha256:")[:24]
        subprocess.run(["docker", "tag", BASE_IMAGE, base_tag], check=True)
        base_info = json.loads(subprocess.check_output(["docker", "image", "inspect", base_tag]))[0]
        assert base_info["Id"] == BASE_IMAGE
        (context / "Dockerfile").write_text(
            f"FROM {base_tag}\nCOPY --chown=65532:65532 payment_app/ /opt/vibesecur/payment_app/\n")
        assert hashlib.sha256((context / "payment_app" / "app.py").read_bytes()).hexdigest() == EXPECTED_SOURCE
        image_file = root / "image-id"
        subprocess.run(["docker", "build", "--pull=false", "--network=none", "--iidfile", str(image_file),
                        "-f", str(context / "Dockerfile"), "-t", "vibesecur-payment-preview:verified", str(context)],
                       check=True, stdout=subprocess.DEVNULL)
        image = image_file.read_text().strip()
        image_info = json.loads(subprocess.check_output(["docker", "image", "inspect", image]))[0]
        base_layers = base_info["RootFS"]["Layers"]
        assert image_info["RootFS"]["Layers"][:len(base_layers)] == base_layers
        source = ("import hashlib,pathlib; print(hashlib.sha256("
                  "pathlib.Path('/opt/vibesecur/payment_app/app.py').read_bytes()).hexdigest())")
        observed = subprocess.check_output(["docker", "run", "--rm", "--pull", "never", "--network", "none",
                                            "--entrypoint", "python", image, "-c", source], text=True).strip()
        result = {"passed": observed == EXPECTED_SOURCE, "imageDigest": image,
                  "sourceSha256": observed, "artifactDigest": hashlib.sha256(PATCH.read_bytes()).hexdigest()}
        Path("artifacts/gates/promotion-build-preview.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result))
        if not result["passed"]:
            raise SystemExit(2)


if __name__ == "__main__":
    main()
