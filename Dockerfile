FROM python:3.12-slim

ARG VERSION=dev
ARG VCS_REF=unknown

LABEL org.opencontainers.image.title="Serket" \
      org.opencontainers.image.description="Active Directory relationship intelligence and attack-path workbench" \
      org.opencontainers.image.vendor="AraizCorp LLC" \
      org.opencontainers.image.source="https://github.com/AraizCorp/Serket" \
      org.opencontainers.image.documentation="https://github.com/AraizCorp/Serket#readme" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SERKET_CONTAINER=1 \
    SERKET_NO_BROWSER=1

WORKDIR /app

RUN groupadd --system serket \
    && useradd --system --gid serket --create-home --home-dir /home/serket serket

COPY requirements.txt ./
RUN python -m pip install --upgrade pip \
    && python -m pip install --requirement requirements.txt

COPY --chown=serket:serket . .
RUN mkdir -p /home/serket/.serket/results \
    && chown -R serket:serket /home/serket/.serket

USER serket

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=4s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3).read()"

ENTRYPOINT ["python", "serket.py"]
CMD ["--serve", "/app/demo/serket-demo.json", "--port", "8080", "--quiet"]
