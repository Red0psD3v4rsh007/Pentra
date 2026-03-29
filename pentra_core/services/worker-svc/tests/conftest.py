from __future__ import annotations

import os
import sys


os.environ["APP_ENV"] = "development"
os.environ["DEBUG"] = "true"

_this_dir = os.path.dirname(os.path.abspath(__file__))
_service_root = os.path.dirname(_this_dir)
_repo_root = os.path.dirname(os.path.dirname(os.path.dirname(_service_root)))
_common_root = os.path.join(_repo_root, "pentra_core", "packages", "pentra-common")

for candidate in (_service_root, _repo_root, _common_root):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)
