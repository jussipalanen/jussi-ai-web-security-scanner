"""FastAPI application layer.

The API layer is a thin adapter: it validates input, calls the engine and shapes
responses. No scanning logic lives here, so the engine stays usable without
FastAPI.
"""
