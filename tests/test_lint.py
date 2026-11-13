"""The cross-organisation access lint, run as a test so `pytest` alone catches a violation."""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("check_unscoped_access", ROOT / "scripts" / "check_unscoped_access.py")
lint = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lint)

pytestmark = pytest.mark.isolation


def test_repository_has_no_unexplained_cross_organisation_access():
    assert lint.violations() == []


@pytest.mark.parametrize(
    "source",
    [
        "rows = Person.all_organisations.filter(name='x')\n",
        "rows = Person._base_manager.all()\n",
        "rows = Person._default_manager.all()\n",
        "rows = Person.objects.raw('select 1')\n",
        "with connection.cursor() as c:\n    pass\n",
        "rows = Person.objects.extra(where=['1=1'])\n",
        "# unscoped: x\nrows = Person.all_organisations.all()\n",  # a reason must say something
    ],
)
def test_lint_catches(tmp_path, source):
    (tmp_path / "hub").mkdir()
    (tmp_path / "hub" / "thing.py").write_text(source)
    assert len(lint.violations(tmp_path)) == 1


@pytest.mark.parametrize(
    "source",
    [
        "rows = Person.all_organisations.all()  # unscoped: nightly platform report\n",
        "# unscoped: nightly platform report\nrows = Person.all_organisations.all()\n",
        "text = 'the all_organisations manager and ._base_manager are mentioned in a string'\n",
        "# a comment that mentions .all_organisations\nx = 1\n",
        "rows = Person.objects.all()\n",
    ],
)
def test_lint_allows(tmp_path, source):
    (tmp_path / "hub").mkdir()
    (tmp_path / "hub" / "thing.py").write_text(source)
    assert lint.violations(tmp_path) == []
