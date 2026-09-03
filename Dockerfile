# syntax=docker/dockerfile:1

# --- build stage -------------------------------------------------------------
# Dependencies are compiled and installed here so the runtime image carries no
# build toolchain.
FROM python:3.12-slim-bookworm AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy only what the build needs first, so dependency layers stay cached when
# source changes.
COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --upgrade pip && pip install .

# --- runtime stage -----------------------------------------------------------
FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

# The scanner makes outbound requests to untrusted hosts. Run it as an
# unprivileged user with no write access to the application directory.
RUN useradd --create-home --shell /usr/sbin/nologin --uid 10001 scanner

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
USER scanner

EXPOSE 8000

# Uses the interpreter already present rather than adding curl to the image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).status == 200 else 1)"

# No --reload: that is a development convenience and watches the filesystem.
CMD ["uvicorn", "jussiai_scanner.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
