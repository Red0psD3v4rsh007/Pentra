# Pentra Knowledge Corpus

This directory holds the learned corpus for the Phase 10 public-source-first
program.

It is split into two layers:

- `raw/`
  - acquisition manifests that describe what Pentra should extract from each
    approved source and why
- `normalized/`
  - structured summaries and facts that preserve source provenance and can be
    consumed by planners, capability packs, and benchmark truth logic

The corpus is intentionally not a dump of copied page bodies.

It stores:

- structured facts
- normalized taxonomies
- benchmark-truth summaries
- short source summaries with provenance

It does not store:

- bulk proprietary content
- large copied textbook bodies
- unguided scraped page archives
