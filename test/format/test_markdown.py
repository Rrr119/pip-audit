import pytest
from packaging.version import Version

import pip_audit._format as format
from pip_audit._format.interface import pypi_url, vuln_id_url
from pip_audit._format.markdown import _md_link
from pip_audit._service import ResolvedDependency


# Shortcuts for building expected output with Markdown links
def _P(name):
    return _md_link(name, pypi_url(name))


def _V(vid):
    return _md_link(vid, vuln_id_url(vid))


@pytest.mark.parametrize("output_desc, output_aliases", ([True, False], [True, False]))
def test_columns_not_manifest(output_desc, output_aliases):
    fmt = format.MarkdownFormat(output_desc, output_aliases)
    assert not fmt.is_manifest


def test_markdown(vuln_data):
    markdown_format = format.MarkdownFormat(True, True)
    expected_markdown = f"""
Name | Version | ID | Fix Versions | Aliases | Description
--- | --- | --- | --- | --- | ---
{_P("foo")} | 1.0 | {_V("VULN-0")} | 1.1,1.4 | {_V("CVE-0000-00000")} | The first vulnerability
{_P("foo")} | 1.0 | {_V("VULN-1")} | 1.0 | {_V("CVE-0000-00001")} | The second vulnerability
{_P("bar")} | 0.1 | {_V("VULN-2")} |  | {_V("CVE-0000-00002")} | The third vulnerability"""
    assert markdown_format.format(vuln_data, []) == expected_markdown


def test_markdown_no_desc(vuln_data):
    markdown_format = format.MarkdownFormat(False, True)
    expected_markdown = f"""
Name | Version | ID | Fix Versions | Aliases
--- | --- | --- | --- | ---
{_P("foo")} | 1.0 | {_V("VULN-0")} | 1.1,1.4 | {_V("CVE-0000-00000")}
{_P("foo")} | 1.0 | {_V("VULN-1")} | 1.0 | {_V("CVE-0000-00001")}
{_P("bar")} | 0.1 | {_V("VULN-2")} |  | {_V("CVE-0000-00002")}"""
    assert markdown_format.format(vuln_data, []) == expected_markdown


def test_markdown_no_desc_no_aliases(vuln_data):
    markdown_format = format.MarkdownFormat(False, False)
    expected_markdown = f"""
Name | Version | ID | Fix Versions
--- | --- | --- | ---
{_P("foo")} | 1.0 | {_V("VULN-0")} | 1.1,1.4
{_P("foo")} | 1.0 | {_V("VULN-1")} | 1.0
{_P("bar")} | 0.1 | {_V("VULN-2")} | """
    assert markdown_format.format(vuln_data, []) == expected_markdown


def test_markdown_skipped_dep(vuln_data_skipped_dep):
    markdown_format = format.MarkdownFormat(False, True)
    expected_markdown = f"""
Name | Version | ID | Fix Versions | Aliases
--- | --- | --- | --- | ---
{_P("foo")} | 1.0 | {_V("VULN-0")} | 1.1,1.4 | {_V("CVE-0000-00000")}

Name | Skip Reason
--- | ---
bar | skip-reason"""
    assert markdown_format.format(vuln_data_skipped_dep, []) == expected_markdown


def test_markdown_no_vuln_data(no_vuln_data):
    markdown_format = format.MarkdownFormat(False, True)
    expected_markdown = ""
    assert markdown_format.format(no_vuln_data, []) == expected_markdown


def test_markdown_no_vuln_data_skipped_dep(no_vuln_data_skipped_dep):
    markdown_format = format.MarkdownFormat(False, True)
    expected_markdown = """
Name | Skip Reason
--- | ---
bar | skip-reason"""
    assert markdown_format.format(no_vuln_data_skipped_dep, []) == expected_markdown


def test_markdown_fix(vuln_data, fix_data):
    markdown_format = format.MarkdownFormat(False, True)
    expected_markdown = f"""
Name | Version | ID | Fix Versions | Applied Fix | Aliases
--- | --- | --- | --- | --- | ---
{_P("foo")} | 1.0 | {_V("VULN-0")} | 1.1,1.4 | Successfully upgraded foo (1.0 => 1.8) | {_V("CVE-0000-00000")}
{_P("foo")} | 1.0 | {_V("VULN-1")} | 1.0 | Successfully upgraded foo (1.0 => 1.8) | {_V("CVE-0000-00001")}
{_P("bar")} | 0.1 | {_V("VULN-2")} |  | Successfully upgraded bar (0.1 => 0.3) | {_V("CVE-0000-00002")}"""
    assert markdown_format.format(vuln_data, fix_data) == expected_markdown


def test_markdown_skipped_fix(vuln_data, skipped_fix_data):
    markdown_format = format.MarkdownFormat(False, True)
    expected_markdown = f"""
Name | Version | ID | Fix Versions | Applied Fix | Aliases
--- | --- | --- | --- | --- | ---
{_P("foo")} | 1.0 | {_V("VULN-0")} | 1.1,1.4 | Successfully upgraded foo (1.0 => 1.8) | {_V("CVE-0000-00000")}
{_P("foo")} | 1.0 | {_V("VULN-1")} | 1.0 | Successfully upgraded foo (1.0 => 1.8) | {_V("CVE-0000-00001")}
{_P("bar")} | 0.1 | {_V("VULN-2")} |  | Failed to fix bar (0.1): skip-reason | {_V("CVE-0000-00002")}"""
    assert markdown_format.format(vuln_data, skipped_fix_data) == expected_markdown


def test_markdown_dependency_chains(vuln_data):
    foo = next(dep for dep in vuln_data if dep.name == "foo")
    root = ResolvedDependency(name="root", version=Version("1.0"))
    middle = ResolvedDependency(name="middle", version=Version("2.0"))
    chains = {foo: [[root, middle, foo]]}

    markdown_format = format.MarkdownFormat(False, False, output_chains=True)
    lines = markdown_format.format(vuln_data, [], chains).splitlines()

    assert lines[1].endswith("| Dependency Chain")
    assert lines[3].endswith("| root==1.0 -> middle==2.0 -> foo==1.0")


def test_markdown_group_by_package(vuln_data):
    markdown_format = format.MarkdownFormat(False, False, group_by_package=True)
    lines = markdown_format.format(vuln_data, []).splitlines()

    assert len(lines) == 5
    assert "VULN-0" in lines[3]
    assert "VULN-1" in lines[3]
    assert "1.1,1.4,1.0" in lines[3]


def test_markdown_group_by_package_with_chains(vuln_data):
    foo = next(dep for dep in vuln_data if dep.name == "foo")
    chains = {foo: [[foo]]}

    markdown_format = format.MarkdownFormat(
        False,
        False,
        output_chains=True,
        group_by_package=True,
    )
    lines = markdown_format.format(vuln_data, [], chains).splitlines()

    assert len(lines) == 5
    assert lines[3].endswith("| foo==1.0")
