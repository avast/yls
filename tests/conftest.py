from pathlib import Path
import pytest


@pytest.fixture(scope="session")
def samples_dir_with_pe(pytestconfig: pytest.Config) -> Path:
    return pytestconfig.rootpath / "tests" / "assets"
