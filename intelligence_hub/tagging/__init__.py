"""Deterministic tagging of feed rows from controlled vocabularies.

Every tag says how it was found (method) and how far to trust it (confidence):

- high: read from a structured field of a primary source, or from the source's own
  identity (KEV dateAdded, a CNA weakness, source_class from config/sources.json).
- medium: an exact, case-sensitive name or term in the headline with no conflicting signal.
- low: derived through a taxonomy chain (CWE to CAPEC to ATT&CK), a weak name confirmed by a
  context word, or exploitation wording in a press headline.

The taggers in fields.py are pure functions of (row, context). There is no network
access, no randomness and no model; the same inputs always give the same tags in the
same order. TAGGER_VERSION changes whenever a rule changes.
"""
from .engine import (TAGGER_VERSION, Context, Fold, build_context, export_fields, long_tags, raw_tags,  # noqa: F401
                     tag_row, tag_rows, v6_tags)
