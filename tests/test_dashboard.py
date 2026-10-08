"""Exercise actual Streamlit rendering and interactions, not just server boot."""

from streamlit.testing.v1 import AppTest
from pathlib import Path
from securecharge.backend import Mode
from securecharge.scenarios import Attack

APP = Path(__file__).resolve().parent.parent / "dashboard.py"


def test_dashboard_default_and_migration_mode_render():
    app = AppTest.from_file(APP, default_timeout=30).run()
    assert not app.exception
    assert len(app.tabs) == 7
    app.sidebar.radio[0].set_value(Mode.MONITOR).run()
    assert not app.exception


def test_dashboard_collision_scenario_and_checksum_selector():
    app = AppTest.from_file(APP, default_timeout=30).run()
    app.sidebar.selectbox[0].set_value("sha256").run()
    next(box for box in app.selectbox if box.label == "Scenario").set_value(Attack.TAMPER_RECOMPUTE_MD5).run()
    assert not app.exception
