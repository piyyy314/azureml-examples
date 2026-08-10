"""
Unit tests for sdk/python/using-mltable/mltable-requirements.txt.

These tests statically validate the pinned package versions in
mltable-requirements.txt (several of which are pinned solely to satisfy
Snyk vulnerability scanning) rather than performing a real `pip install`,
since installing the full mltable/azureml-dataprep dependency chain is not
appropriate for a fast unit-test suite.
"""
import os
import re

import pytest

REQUIREMENTS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "mltable-requirements.txt"
)

# Minimum versions currently pinned in the requirements file (Snyk fixes).
# urllib3, cryptography, and requests were bumped by this PR; the rest were
# already at these minimums and should remain unchanged.
EXPECTED_MIN_VERSIONS = {
    "urllib3": "2.7.0",
    "pyjwt": "2.11.0",
    "cryptography": "48.0.1",
    "azure-core": "1.38.0",
    "zipp": "3.19.1",
    "requests": "2.33.0",
    "azure-identity": "1.16.1",
    "idna": "3.15",
}

# Packages pinned to an exact version rather than a lower bound.
EXPECTED_EXACT_VERSIONS = {
    "mltable": "1.5.0",
    "azureml-dataprep": "4.10.6",
}

# Minimum versions that were replaced by this PR because they were flagged
# as vulnerable. The new pins must never regress back down to these.
PREVIOUSLY_VULNERABLE_MIN_VERSIONS = {
    "urllib3": "1.26.19",
    "cryptography": "41.0.0",
    "requests": "2.32.2",
}

SNYK_PINNED_PACKAGES = {
    "urllib3",
    "pyjwt",
    "cryptography",
    "azure-core",
    "zipp",
    "requests",
    "azure-identity",
    "idna",
}

REQUIREMENT_LINE_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9_.-]+)(?P<extras>\[[^\]]*\])?"
    r"(?P<op>==|>=)(?P<version>[0-9][0-9A-Za-z.]*)"
    r"\s*(?:#.*)?$"
)


def _version_tuple(version):
    return tuple(int(part) for part in version.split("."))


@pytest.fixture()
def requirements_lines():
    with open(REQUIREMENTS_PATH, "r") as f:
        return [line.rstrip("\n") for line in f]


@pytest.fixture()
def requirements_content():
    with open(REQUIREMENTS_PATH, "r") as f:
        return f.read()


@pytest.fixture()
def parsed_requirements(requirements_lines):
    """Map lower-cased package name -> (operator, version) for every
    non-blank, non-comment-only line in the requirements file."""
    parsed = {}
    for line in requirements_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = REQUIREMENT_LINE_RE.match(stripped)
        assert match, f"Could not parse requirement line: {line!r}"
        parsed[match.group("name").lower()] = (
            match.group("op"),
            match.group("version"),
        )
    return parsed


def test_requirements_file_exists():
    assert os.path.isfile(
        REQUIREMENTS_PATH
    ), f"mltable-requirements.txt not found at {REQUIREMENTS_PATH}"


def test_requirements_file_not_empty(requirements_content):
    assert requirements_content.strip(), "mltable-requirements.txt is empty"


def test_all_lines_are_parsable_requirements(requirements_lines):
    for line in requirements_lines:
        stripped = line.strip()
        if not stripped:
            continue
        assert REQUIREMENT_LINE_RE.match(
            stripped
        ), f"Line does not look like a valid requirement spec: {line!r}"


def test_no_duplicate_packages(requirements_lines):
    names = []
    for line in requirements_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = REQUIREMENT_LINE_RE.match(stripped)
        names.append(match.group("name").lower())
    assert len(names) == len(set(names)), f"Duplicate package entries found: {names}"


@pytest.mark.parametrize("package,expected_version", EXPECTED_EXACT_VERSIONS.items())
def test_exact_pinned_versions(parsed_requirements, package, expected_version):
    assert package in parsed_requirements, f"{package} missing from requirements file"
    op, version = parsed_requirements[package]
    assert op == "==", f"{package} expected to be pinned with '==', found '{op}'"
    assert version == expected_version


@pytest.mark.parametrize("package,expected_min", EXPECTED_MIN_VERSIONS.items())
def test_minimum_pinned_versions(parsed_requirements, package, expected_min):
    assert package in parsed_requirements, f"{package} missing from requirements file"
    op, version = parsed_requirements[package]
    assert op == ">=", f"{package} expected to use '>=', found '{op}'"
    assert version == expected_min, (
        f"{package} minimum version changed unexpectedly: "
        f"expected {expected_min}, found {version}"
    )


@pytest.mark.parametrize(
    "package,vulnerable_min", PREVIOUSLY_VULNERABLE_MIN_VERSIONS.items()
)
def test_does_not_regress_to_previously_vulnerable_versions(
    parsed_requirements, package, vulnerable_min
):
    # Regression test: urllib3, cryptography, and requests were bumped in
    # this PR to remediate Snyk-flagged vulnerabilities. The pinned minimum
    # must stay strictly above the old, vulnerable minimum.
    _, version = parsed_requirements[package]
    assert _version_tuple(version) > _version_tuple(vulnerable_min), (
        f"{package}>={version} regresses to the previously vulnerable "
        f"minimum {vulnerable_min}"
    )


def test_unchanged_snyk_pins_still_present(parsed_requirements):
    # These constraints were not touched by this PR and should remain
    # exactly as they were.
    unchanged = {
        "pyjwt": (">=", "2.11.0"),
        "azure-core": (">=", "1.38.0"),
        "zipp": (">=", "3.19.1"),
        "azure-identity": (">=", "1.16.1"),
        "idna": (">=", "3.15"),
    }
    for package, expected in unchanged.items():
        assert parsed_requirements[package] == expected


@pytest.mark.parametrize("package", sorted(SNYK_PINNED_PACKAGES))
def test_snyk_pin_has_justification_comment(requirements_lines, package):
    matching_lines = [
        line
        for line in requirements_lines
        if REQUIREMENT_LINE_RE.match(line.strip())
        and REQUIREMENT_LINE_RE.match(line.strip()).group("name").lower() == package
    ]
    assert matching_lines, f"{package} not found in requirements file"
    assert "pinned by Snyk to avoid a vulnerability" in matching_lines[0], (
        f"Missing Snyk justification comment for {package}: {matching_lines[0]!r}"
    )


def test_azureml_dataprep_has_pandas_extra(requirements_lines):
    dataprep_lines = [
        line
        for line in requirements_lines
        if line.strip().lower().startswith("azureml-dataprep")
    ]
    assert len(dataprep_lines) == 1
    assert "[pandas]" in dataprep_lines[0]


def test_no_unresolved_merge_markers(requirements_content):
    for marker in ("<<<<<<<", "=======", ">>>>>>>"):
        assert marker not in requirements_content