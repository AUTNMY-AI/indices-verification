"""
indices-verification: independently verify The Road to Autonomy Indices.

Given only the public files published for a sealed cycle (cells.json, tree.json,
and the RFC 3161 reply tokens root-*.tsr), this tool recomputes the Merkle root
from the published values and confirms it matches the externally anchored
timestamp, with no trust in AUTNMY AI required.

It proves integrity (values were not altered after sealing) and timing (they
existed at the certified time). It does NOT assess correctness; that is governed
by the Benchmark Statement and methodology.
"""
__version__ = "0.1.0"
