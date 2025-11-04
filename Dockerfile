FROM python:3.13-slim-bullseye

WORKDIR /app
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        iptables \
        iproute2 \
        iputils-ping \
        procps \
        curl \
        ca-certificates && \
    curl --version && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    update-ca-certificates
COPY src /app
RUN which curl && \
    which ping && \
    which iptables

