from __future__ import annotations

import os
import sys
import uuid
from types import SimpleNamespace


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def test_attach_asset_counts_applies_real_counts_to_projects():
    from app.services.project_service import _attach_asset_counts

    project_a = SimpleNamespace(id=uuid.uuid4(), asset_count=0)
    project_b = SimpleNamespace(id=uuid.uuid4(), asset_count=0)

    projects = _attach_asset_counts(
        [project_a, project_b],
        {
            project_a.id: 3,
        },
    )

    assert projects[0].asset_count == 3
    assert projects[1].asset_count == 0
