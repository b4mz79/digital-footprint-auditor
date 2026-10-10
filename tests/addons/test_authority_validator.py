from __future__ import annotations

from pathlib import Path

import pytest

from services.addonsmgr.authority_validator import validate_package_authority


def _package(root: Path, **files: str) -> Path:
    root.mkdir()
    for relative, source in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source, encoding="utf-8")
    return root


def test_authority_gate_accepts_just_sample_style_imports(tmp_path: Path) -> None:
    root = _package(
        tmp_path / "package",
        **{
            "manifest.json": "{}",
            "plugin.py": (
                "from __future__ import annotations\n"
                "from typing import Any, Mapping\n"
                "def run(context: Mapping[str, Any]) -> dict[str, int]:\n"
                "    return {'count': 1}\n"
            ),
            "ui.py": (
                "from typing import Any, Mapping\n"
                "import streamlit as st\n"
                "def render(context: Mapping[str, Any]) -> None:\n"
                "    st.info('ok')\n"
            ),
            "helpers/math.txt": "static data",
        },
    )

    validate_package_authority(root)


@pytest.mark.parametrize(
    "source",
    [
        "import os\n",
        "import socket\n",
        "import requests\n",
        "from subprocess import run\n",
    ],
)
def test_authority_gate_rejects_non_allowlisted_imports_in_any_python_file(
    tmp_path: Path,
    source: str,
) -> None:
    root = _package(
        tmp_path / "package",
        **{
            "plugin.py": "def run(context): return {}\n",
            "helpers/hidden.py": source,
        },
    )

    with pytest.raises(ValueError, match="import is not allowlisted"):
        validate_package_authority(root)


@pytest.mark.parametrize(
    "source",
    [
        "def run(context): return open('/tmp/x').read()\n",
        "def run(context): return eval('1 + 1')\n",
        "def run(context): return __import__('os')\n",
        "def run(context):\n    global state\n    state = {}\n",
    ],
)
def test_authority_gate_rejects_dynamic_or_unrestricted_operations(
    tmp_path: Path,
    source: str,
) -> None:
    root = _package(tmp_path / "package", **{"plugin.py": source})

    with pytest.raises(ValueError, match="not allowlisted|static authority gate"):
        validate_package_authority(root)


@pytest.mark.parametrize("filename", ["payload.exe", "module.pyc", "library.dll", "script.js"])
def test_authority_gate_rejects_unsupported_file_types(
    tmp_path: Path,
    filename: str,
) -> None:
    root = _package(
        tmp_path / "package",
        **{"plugin.py": "def run(context): return {}\n", filename: "payload"},
    )

    with pytest.raises(ValueError, match="unsupported file type"):
        validate_package_authority(root)


def test_authority_gate_rejects_invalid_python_in_helper_file(tmp_path: Path) -> None:
    root = _package(
        tmp_path / "package",
        **{
            "plugin.py": "def run(context): return {}\n",
            "nested/helper.py": "def broken(:\n",
        },
    )

    with pytest.raises(ValueError, match="cannot be parsed"):
        validate_package_authority(root)


@pytest.mark.parametrize(
    "source",
    [
        "import streamlit.runtime\n",
        "def run(context): return st.secrets\n",
        "def run(context): return object.__subclasses__()\n",
    ],
)
def test_authority_gate_rejects_host_internals_and_reflection(
    tmp_path: Path,
    source: str,
) -> None:
    root = _package(
        tmp_path / "package",
        **{"plugin.py": "import streamlit as st\n" + source},
    )

    with pytest.raises(ValueError, match="not allowlisted|static authority gate"):
        validate_package_authority(root)


def test_authority_gate_allows_sibling_path_lifecycle_logging(tmp_path: Path) -> None:
    root = _package(
        tmp_path / "package",
        **{
            "plugin.py": (
                "from pathlib import Path\n"
                "_LOG = Path(__file__).with_name('lifecycle.log')\n"
                "def after_install(context):\n"
                "    with _LOG.open('a', encoding='utf-8') as handle:\n"
                "        handle.write('ok\\n')\n"
            ),
        },
    )

    validate_package_authority(root)


@pytest.mark.parametrize(
    "source",
    [
        "from pathlib import Path\ndef run(context): Path('/tmp/outside.txt').write_text('x')\n",
        "from pathlib import Path\ndef run(context): Path(__file__).parent.parent.joinpath('outside.txt').write_text('x')\n",
        "from pathlib import Path\ndef run(context): Path(__file__).read_text()\n",
    ],
)
def test_authority_gate_rejects_unconfined_path_access(
    tmp_path: Path,
    source: str,
) -> None:
    root = _package(tmp_path / "package", **{"plugin.py": source})

    with pytest.raises(ValueError, match="filesystem access must use a literal sibling path"):
        validate_package_authority(root)

@pytest.mark.parametrize(
    "source",
    [
        (
            "from pathlib import Path\n"
            "_LOG = Path(__file__).with_name('lifecycle.log')\n"
            "def run(context):\n"
            "    _LOG = Path('/tmp/outside.txt')\n"
            "    _LOG.write_text('x')\n"
        ),
        (
            "from pathlib import Path\n"
            "_LOG = Path(__file__).with_name('lifecycle.log')\n"
            "def run(_LOG):\n"
            "    _LOG.write_text('x')\n"
        ),
        (
            "from pathlib import Path\n"
            "_LOG = Path(__file__).with_name('lifecycle.log')\n"
            "def run(context):\n"
            "    for _LOG in context:\n"
            "        _LOG.write_text('x')\n"
        ),
        (
            "from pathlib import Path\n"
            "_LOG = Path(__file__).with_name('lifecycle.log')\n"
            "def run(context):\n"
            "    try:\n"
            "        raise RuntimeError()\n"
            "    except Exception as _LOG:\n"
            "        _LOG.write_text('x')\n"
        ),
        (
            "from pathlib import Path\n"
            "_LOG = Path(__file__).with_name('lifecycle.log')\n"
            "def _LOG(context):\n"
            "    return None\n"
            "_LOG.write_text('x')\n"
        ),
    ],
)
def test_authority_gate_rejects_rebinding_or_shadowing_local_path_names(
    tmp_path: Path,
    source: str,
) -> None:
    root = _package(tmp_path / "package", **{"plugin.py": source})

    with pytest.raises(ValueError, match="local path variable may not be (rebound|shadowed)"):
        validate_package_authority(root)



@pytest.mark.parametrize(
    "link_method",
    ["symlink_to", "hardlink_to", "link_to", "replace"],
)
def test_authority_gate_rejects_path_link_and_redirect_operations(
    tmp_path: Path,
    link_method: str,
) -> None:
    plugin_source = f"""from pathlib import Path
_LOG = Path(__file__).with_name('lifecycle.log')
def run(context):
    _LOG.{link_method}('/tmp/sensitive.txt')
    return _LOG.read_text()
"""
    root = _package(
        tmp_path / "package",
        **{"plugin.py": plugin_source},
    )

    with pytest.raises(ValueError, match=f"forbidden API call \\.{link_method}\\(\\)"):
        validate_package_authority(root)


@pytest.mark.parametrize(
    "source",
    [
        (
            "from pathlib import Path\n"
            "def run(context):\n"
            "    return '{0.exists.__globals__[os].environ}'.format(Path('x'))\n"
        ),
        (
            "def run(context):\n"
            "    return '{value.__class__}'.format_map({'value': context})\n"
        ),
    ],
)
def test_authority_gate_rejects_format_string_attribute_traversal(
    tmp_path: Path,
    source: str,
) -> None:
    root = _package(tmp_path / "package", **{"plugin.py": source})

    with pytest.raises(ValueError, match="forbidden API call \\.(format|format_map)\\(\\)"):
        validate_package_authority(root)
