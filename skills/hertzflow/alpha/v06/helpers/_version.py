"""Single source of truth for skill version.

Both forensic_pipeline.py (writes `_schema_version` into skeleton) and
update_check.py (compares against latest GitHub tag) read from here, so
release bumps only touch one file.
"""

__version__ = "1.2.6"
