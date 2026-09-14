"""Cadence is a sealed leaf field and must be read from cells.json.

Regression: _ordered_leaf_bytes used to omit cadence, so build_leaf always
defaulted to "12h". Editing cadence in a published cycle still produced the
original Merkle root and verify-cycle reported VERIFIED.
"""
from __future__ import annotations

import copy
import unittest

from indices_verification import canonical as C
from indices_verification import merkle as M
from indices_verification.cli import _ordered_leaf_bytes


def _cell(**overrides):
    cell = {
        "index": "robotaxi",
        "methodology_version": "robotaxi-1.3",
        "operator": "waymo",
        "composite": "77.2",
        "pillars": {"safety": "80.0", "scale": "70.0"},
        "cadence": "12h",
        "computed_at_utc": "2026-09-03T06:00:00Z",
    }
    cell.update(overrides)
    return cell


def _root(cells_doc):
    leaf_bytes, _ = _ordered_leaf_bytes(cells_doc)
    return M.merkle_root(leaf_bytes)


class CadenceIsSealed(unittest.TestCase):
    def test_published_cadence_is_hashed_into_the_leaf(self):
        clean = {"cells": [_cell()]}
        tampered = {"cells": [_cell(cadence="24h")]}
        self.assertNotEqual(_root(clean), _root(tampered))

    def test_missing_cadence_defaults_to_locked_12h(self):
        with_field = {"cells": [_cell(cadence="12h")]}
        omitted = {"cells": [_cell()]}
        del omitted["cells"][0]["cadence"]
        self.assertEqual(_root(with_field), _root(omitted))

    def test_composite_tamper_still_changes_the_root(self):
        clean = {"cells": [_cell()]}
        tampered = {"cells": [_cell(composite="10.0")]}
        self.assertNotEqual(_root(clean), _root(tampered))

    def test_leaf_carries_the_published_cadence(self):
        _, leaves = _ordered_leaf_bytes({"cells": [_cell(cadence="24h")]})
        self.assertEqual(leaves[0]["cadence"], "24h")
        self.assertEqual(
            C.canonical_bytes(leaves[0]),
            C.canonical_bytes(
                C.build_leaf(
                    index="robotaxi",
                    methodology_version="robotaxi-1.3",
                    operator="waymo",
                    composite="77.2",
                    pillars={"safety": "80.0", "scale": "70.0"},
                    computed_at_utc="2026-09-03T06:00:00Z",
                    cadence="24h",
                )
            ),
        )

    def test_multi_cell_cadence_edit_does_not_preserve_root(self):
        clean = {
            "cells": [
                _cell(operator="waymo", composite="77.2"),
                _cell(operator="cruise", composite="60.1"),
            ]
        }
        tampered = copy.deepcopy(clean)
        tampered["cells"][1]["cadence"] = "24h"
        self.assertNotEqual(_root(clean), _root(tampered))


if __name__ == "__main__":
    unittest.main()
