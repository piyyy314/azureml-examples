"""
Unit tests for sdk/python/using-mltable/mltable-requirements.txt

This requirements file is used to install the packages needed to run the
mltable sample notebooks. These tests validate its structure and content,
in particular the version pins added to remediate vulnerabilities flagged
by Snyk (see PR that bumped mltable to 1.5.0 and pinned several transitive
dependencies).
"""
import os

import pytest
from packaging.requirements import Requirement
from packaging.version import Version

REQUIREMENTS_PATH = os.path.join(os.path.dirname(__file__), "mltable-requirements.txt")

# Direct dependencies that must be pinned to an exact version.
EXPECTED_DIRECT_PINS = {
    "mltable": "1.5.0",
    "azureml-dataprep": "4.10.6",
}

# Transitive dependencies pinned by Snyk to a minimum version to avoid a
# known vulnerability.
EXPECTED_MIN_VERSIONS = {
    "urllib3": "1.26.19",
    "pyjwt": "2.11.0",
    "cryptography": "41.0.0",
    "azure-core": "1.38.0",
    "zipp": "3.19.1",
    "requests": "2.32.2",
    "azure-identity": "1.16.1",
    "idna": "3.15",
}


def _read_lines():
    with open(REQUIREMENTS_PATH, "r", encoding="utf-8") as f:
        return [line.rstrip("\n") for line in f if line.strip()]


def _split_requirement_and_comment(line):
    """Split a requirements.txt line into (requirement_str, comment_or_None)."""
    if "#" in line:
        req_part, comment = line.split("#", 1)
        return req_part.strip(), comment.strip()
    return line.strip(), None


def _parsed_requirements():
    """Return a dict of {lowercased_package_name: packaging.requirements.Requirement}."""
    parsed = {}
    for line in _read_lines():
        req_str, _ = _split_requirement_and_comment(line)
        req = Requirement(req_str)
        parsed[req.name.lower()] = req
    return parsed


class TestMltableRequirementsFileStructure:
    def test_file_exists(self):
        assert os.path.isfile(REQUIREMENTS_PATH)

    def test_file_is_not_empty(self):
        with open(REQUIREMENTS_PATH, "r", encoding="utf-8") as f:
            content = f.read()
        assert content.strip() != ""

    def test_all_lines_parse_as_valid_requirements(self):
        for line in _read_lines():
            req_str, _ = _split_requirement_and_comment(line)
            # Requirement() raises InvalidRequirement if the line is malformed.
            req = Requirement(req_str)
            assert req.name

    def test_no_duplicate_package_entries(self):
        names = []
        for line in _read_lines():
            req_str, _ = _split_requirement_and_comment(line)
            names.append(Requirement(req_str).name.lower())
        assert len(names) == len(set(names)), f"Duplicate packages found: {names}"

    def test_no_blank_lines(self):
        with open(REQUIREMENTS_PATH, "r", encoding="utf-8") as f:
            raw_lines = f.readlines()
        assert all(
            line.strip() for line in raw_lines
        ), "mltable-requirements.txt should not contain blank lines"

    def test_expected_package_count(self):
        # 2 direct dependencies + 8 Snyk-pinned transitive dependencies.
        parsed = _parsed_requirements()
        assert len(parsed) == len(EXPECTED_DIRECT_PINS) + len(EXPECTED_MIN_VERSIONS)


class TestDirectDependencyPins:
    def test_direct_dependencies_present(self):
        parsed = _parsed_requirements()
        for pkg in EXPECTED_DIRECT_PINS:
            assert pkg in parsed, f"Expected direct dependency '{pkg}' not found"

    @pytest.mark.parametrize("pkg,expected_version", list(EXPECTED_DIRECT_PINS.items()))
    def test_direct_dependency_is_exact_pinned(self, pkg, expected_version):
        parsed = _parsed_requirements()
        req = parsed[pkg]
        specs = list(req.specifier)
        assert len(specs) == 1, f"Expected exactly one version specifier for {pkg}"
        assert specs[0].operator == "==", f"{pkg} must be pinned with '=='"
        assert specs[0].version == expected_version

    def test_azureml_dataprep_has_pandas_extra(self):
        parsed = _parsed_requirements()
        req = parsed["azureml-dataprep"]
        assert "pandas" in req.extras

    def test_mltable_version_upgraded_from_1_3_0(self):
        # Regression guard: the PR bumps mltable from 1.3.0 to 1.5.0.
        parsed = _parsed_requirements()
        specs = list(parsed["mltable"].specifier)
        assert specs[0].version != "1.3.0"
        assert Version(specs[0].version) > Version("1.3.0")


class TestSnykPinnedTransitiveDependencies:
    def test_all_expected_transitive_dependencies_present(self):
        parsed = _parsed_requirements()
        for pkg in EXPECTED_MIN_VERSIONS:
            assert pkg in parsed, f"Expected Snyk-pinned dependency '{pkg}' not found"

    @pytest.mark.parametrize("pkg,min_version", list(EXPECTED_MIN_VERSIONS.items()))
    def test_transitive_dependency_minimum_version(self, pkg, min_version):
        parsed = _parsed_requirements()
        req = parsed[pkg]
        specs = list(req.specifier)
        assert len(specs) == 1, f"Expected exactly one version specifier for {pkg}"
        assert specs[0].operator == ">=", f"{pkg} must use a '>=' minimum version pin"
        assert Version(specs[0].version) >= Version(min_version)

    @pytest.mark.parametrize("pkg", list(EXPECTED_MIN_VERSIONS))
    def test_transitive_dependency_has_snyk_explanation_comment(self, pkg):
        for line in _read_lines():
            req_str, comment = _split_requirement_and_comment(line)
            if Requirement(req_str).name.lower() == pkg:
                assert comment is not None, f"Missing explanatory comment for {pkg}"
                assert "snyk" in comment.lower()
                assert "vulnerability" in comment.lower()
                assert "not directly required" in comment.lower()
                return
        pytest.fail(f"Could not find line for package {pkg}")

    def test_no_unexpected_extra_transitive_pins(self):
        # Ensures every non-direct entry in the file is one we explicitly expect,
        # catching accidental/unreviewed additions.
        parsed = _parsed_requirements()
        transitive_names = set(parsed) - set(EXPECTED_DIRECT_PINS)
        assert transitive_names == set(EXPECTED_MIN_VERSIONS)
