# Quarantined Runtime Tree

This directory is intentionally parked outside Pentra's canonical runtime path.

- It is retained only for historical reference and controlled recovery work.
- Production and local supported runtime code must not import from this tree.
- The canonical runtime path is documented in `pentra_core/docs/runtime_ownership_map.md`.

If logic here is needed again, it should be reintroduced into the supported engine
modules explicitly instead of being imported directly from `_experimental`.
