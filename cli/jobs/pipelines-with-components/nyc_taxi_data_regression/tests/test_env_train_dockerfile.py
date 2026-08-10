"""
Unit tests for the env_train Dockerfile used by the nyc_taxi_data_regression
pipeline sample (cli/jobs/pipelines-with-components/nyc_taxi_data_regression/env_train/Dockerfile).

These tests statically validate the contents of the Dockerfile (base image,
OS security update step, and pip dependency installation) rather than
building the image, since building a full Docker image is not appropriate
for a fast unit-test suite.
"""
import os
import re

import pytest

DOCKERFILE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "env_train", "Dockerfile"
)

EXPECTED_BASE_IMAGE = "python:3.15-rc-slim-trixie"

EXPECTED_PIP_PACKAGES = [
    "matplotlib>=3.3,<3.4",
    "psutil>=5.8,<5.9",
    "tqdm>=4.59,<4.60",
    "pandas>=1.1,<1.2",
    "scipy>=1.5,<1.6",
    "numpy>=1.10,<1.20",
    "ipykernel~=6.0",
    "azureml-core",
    "azureml-defaults",
    "azureml-mlflow",
    "azureml-telemetry",
    "scikit-learn==1.2.2",
]


@pytest.fixture()
def dockerfile_lines():
    with open(DOCKERFILE_PATH, "r") as f:
        return f.readlines()


@pytest.fixture()
def dockerfile_content():
    with open(DOCKERFILE_PATH, "r") as f:
        return f.read()


def _non_blank_non_comment_lines(lines):
    return [
        line.strip()
        for line in lines
        if line.strip() and not line.strip().startswith("#")
    ]


def test_dockerfile_exists():
    assert os.path.isfile(DOCKERFILE_PATH), f"Dockerfile not found at {DOCKERFILE_PATH}"


def test_from_instruction_is_first_statement(dockerfile_lines):
    instructions = _non_blank_non_comment_lines(dockerfile_lines)
    assert instructions, "Dockerfile has no instructions"
    assert instructions[0].startswith(
        "FROM "
    ), "The first non-comment instruction in the Dockerfile must be FROM"


def test_base_image_matches_expected_version(dockerfile_lines):
    instructions = _non_blank_non_comment_lines(dockerfile_lines)
    from_line = instructions[0]
    base_image = from_line.split(None, 1)[1].strip()
    assert base_image == EXPECTED_BASE_IMAGE


def test_base_image_is_not_previous_vulnerable_version(dockerfile_content):
    # Regression test: this repo previously pinned to python:3.14.6, which
    # was replaced due to OS-level CVEs. Make sure it doesn't regress back.
    assert "python:3.14.6" not in dockerfile_content


def test_base_image_tag_is_pinned(dockerfile_lines):
    # The base image tag should be an explicit version, never "latest" or
    # untagged, so builds are reproducible and auditable.
    instructions = _non_blank_non_comment_lines(dockerfile_lines)
    from_line = instructions[0]
    base_image = from_line.split(None, 1)[1].strip()
    assert ":" in base_image, "Base image must have an explicit tag"
    tag = base_image.split(":", 1)[1]
    assert tag not in ("", "latest")


def test_base_image_tag_format(dockerfile_lines):
    instructions = _non_blank_non_comment_lines(dockerfile_lines)
    from_line = instructions[0]
    base_image = from_line.split(None, 1)[1].strip()
    assert re.match(
        r"^python:\d+\.\d+(-rc)?-slim-trixie$", base_image
    ), f"Unexpected base image tag format: {base_image}"


def test_os_security_update_step_present(dockerfile_content):
    assert (
        "apt-get update && apt-get upgrade -y && apt-get clean "
        "&& rm -rf /var/lib/apt/lists/*"
    ) in dockerfile_content


def test_os_security_update_step_documented(dockerfile_content):
    # A comment explaining the purpose of the security update step should
    # precede the RUN instruction.
    assert "install OS security updates" in dockerfile_content


def test_pip_install_instruction_present(dockerfile_content):
    assert "RUN pip install" in dockerfile_content


@pytest.mark.parametrize("package", EXPECTED_PIP_PACKAGES)
def test_expected_pip_package_present(dockerfile_content, package):
    assert f"'{package}'" in dockerfile_content


def test_no_unexpected_pip_packages(dockerfile_content):
    quoted_packages = re.findall(r"'([^']+)'", dockerfile_content)
    assert sorted(quoted_packages) == sorted(EXPECTED_PIP_PACKAGES)


def test_dockerfile_has_no_unresolved_merge_markers(dockerfile_content):
    for marker in ("<<<<<<<", "=======", ">>>>>>>"):
        assert marker not in dockerfile_content