# Test runner image for agentic-sdlc's Docker sandbox (no network at run time).
# Add your project's test dependencies here; the agent cannot install packages.
FROM python:3.12-slim
RUN pip install --no-cache-dir pytest==8.3.3
USER 65534:65534
WORKDIR /work
