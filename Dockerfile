# Mr. Deffult | Linux Security & Compliance Pipeline - auditor image
# Default user is unprivileged. For a full host audit run as root with a read-only host mount:
#   docker run --rm --user 0:0 --net=host --pid=host -v /:/host:ro IMAGE --root /host --network on
FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="linux-security-audit" \
      org.opencontainers.image.description="Read-only Linux hardening auditor with JSON/HTML reporting and CI gate" \
      org.opencontainers.image.vendor="Mr. Deffult" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --system --gid 10001 auditor \
 && useradd --system --uid 10001 --gid auditor --no-create-home --shell /usr/sbin/nologin auditor

WORKDIR /opt/mrdeffult
COPY --chown=root:root --chmod=0755 audit/linux_audit.py audit/hardening.sh ./

USER auditor
ENTRYPOINT ["python3", "/opt/mrdeffult/linux_audit.py"]
CMD ["--help"]
