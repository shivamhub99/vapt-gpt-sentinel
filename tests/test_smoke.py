"""Basic smoke test verifying testing environment and package discovery."""

import sentinel


def test_package_import():
    assert sentinel.__version__ == "0.1.0"
