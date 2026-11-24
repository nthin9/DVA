# If DVA ever ran this file, the test that scans this project would see the marker.
from pathlib import Path

Path(__file__).with_name("SETUP_PY_WAS_EXECUTED").write_text("executed")
