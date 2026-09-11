FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

COPY pyproject.toml README.md ./
COPY aegis ./aegis
RUN pip install --no-cache-dir -e .

# Run unprivileged: this process sees every prompt and every response that
# passes through it, which makes it a high-value target in its own right.
RUN useradd -r -u 10001 aegis && mkdir -p /app/data && chown -R aegis /app/data
USER aegis

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=2).status==200 else 1)"

CMD ["python", "-m", "aegis.main"]
