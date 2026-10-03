"""
AI-SOC Ingestion Module
-----------------------
Provides file format detection, multi-format parsing, schema mapping,
and the top-level pipeline entrypoint.

Lazy-import ``run_ingestion`` so the sub-packages can be imported
independently before ``pipeline.py`` is written.
"""


def run_ingestion(*args, **kwargs):  # type: ignore[no-untyped-def]
    """Lazy proxy — delegates to pipeline.run_ingestion at call time."""
    from .pipeline import run_ingestion as _run  # noqa: PLC0415
    return _run(*args, **kwargs)


__all__ = ["run_ingestion"]
