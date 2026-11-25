# Image des services de l'agent (API FastAPI et interface Streamlit) — ENF-08
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Utilisateur sans privilèges ; seules les données d'exécution sont inscriptibles.
RUN useradd --create-home --uid 1000 investigator \
    && mkdir -p /app/investigation_lab/data /app/investigation_lab/runs \
    && chown -R investigator:investigator /app/investigation_lab
USER investigator

EXPOSE 8000 8501

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://localhost:8000/health', timeout=4)" || exit 1

CMD ["uvicorn", "app.api:app", "--host", "0.0.0.0", "--port", "8000"]
