import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))


def test_scheduler_imports_cleanly():
    """Validate scheduler import path without starting background threads."""
    from src.scheduler import start_scheduler

    assert callable(start_scheduler)


def test_app_imports_without_cycle_errors():
    """Validate app import graph remains cycle-safe."""
    from web.app import app

    assert app is not None
