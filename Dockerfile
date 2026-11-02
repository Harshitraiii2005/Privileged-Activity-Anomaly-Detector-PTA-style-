# One image for both services (API and dashboard). Serving needs no torch:
# the served model is rules + IsolationForest; the autoencoder is offline-only.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
# Non-root runtime user. /app is writable for data/ and artifacts/; code stays root-owned (read-only).
# /data is created here so a fresh named volume inherits the user's ownership.
RUN useradd --create-home --uid 10001 privguard \
 && mkdir /data && chown privguard /app /data

# 1) Dependencies only, read from pyproject.toml: this layer is cached until the dependencies change.
COPY pyproject.toml ./
RUN python -c "import tomllib; p = tomllib.load(open('pyproject.toml', 'rb'))['project']; \
extra = p['optional-dependencies']; print('\n'.join(p['dependencies'] + extra['api'] + extra['dashboard']))" \
    > /tmp/requirements.txt \
 && pip install -r /tmp/requirements.txt

# 2) Source. Editable install keeps the code in /app/src, next to config.toml, so default paths resolve.
COPY README.md config.toml ./
COPY src ./src
RUN pip install --no-deps -e .

# 3) Reproducible, self-contained image: generate the seeded dataset and train the scorer at build time.
USER privguard
RUN python -m privguard.synthetic && python -m privguard.scorer

ENV PRIVGUARD_DB_PATH=/data/privguard.db
EXPOSE 8000 8501
CMD ["uvicorn", "privguard.api:app", "--host", "0.0.0.0", "--port", "8000"]
