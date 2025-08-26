FROM golang:latest AS builder

WORKDIR /defender

COPY . .

ENV GOOS=linux

RUN go build -o madsecurity.defender . && \
    chmod +x madsecurity.defender

FROM ubuntu:latest

WORKDIR /defender

COPY --from=builder /defender/madsecurity.defender .
COPY --from=builder /defender/public public/.
COPY --from=builder /defender/services/controllers/server/abort/public services/controllers/server/abort/public/.

ARG APP_USER=defender
ARG UID=10001
ARG GID=10001

RUN apt-get update && \
    apt-get install -y --no-install-recommends openssl && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -g ${GID} ${APP_USER} && \
    useradd -u ${UID} -g ${GID} -m -s /usr/sbin/nologin ${APP_USER} && \
    mkdir history tls && \
    openssl genrsa -out tls/server.key 4096 && \
    openssl req -new -key tls/server.key -out tls/server.csr -subj "/CN=defender" && \
    openssl x509 -req -days 365 -in tls/server.csr -signkey tls/server.key -out tls/server.crt && \
    chown -R ${UID}:${GID} /defender && \
    chmod 600 /defender/tls/server.key && \
    chmod 644 /defender/tls/server.crt

EXPOSE 9947 9948

USER ${UID}:${GID}

ENV DEFENDER_APP_INFO_ENABLE=true \
    \
    DEFENDER_SERVER_TLS_ENABLE=true \
    DEFENDER_SERVER_TLS_KEY=tls/server.key \
    DEFENDER_SERVER_TLS_CRT=tls/server.crt \
    DEFENDER_SERVER_HOST= \
    DEFENDER_SERVER_PORT=9947 \
    DEFENDER_SERVER_PREFIX="/defender" \
    DEFENDER_SERVER_HEALTH="/health" \
    DEFENDER_SERVER_HEALTH_METHOD=post \
    DEFENDER_SERVER_INSPECT="/inspect" \
    DEFENDER_SERVER_INSPECT_METHOD=post \
    DEFENDER_SERVER_APPLY="/apply" \
    DEFENDER_SERVER_APPLY_METHOD=patch \
    DEFENDER_SERVER_REVOKE="/revoke" \
    DEFENDER_SERVER_REVOKE_METHOD=delete \
    DEFENDER_SERVER_IMPLEMENT="/implement" \
    DEFENDER_SERVER_IMPLEMENT_METHOD=patch \
    DEFENDER_SERVER_SUSPEND="/suspend" \
    DEFENDER_SERVER_SUSPEND_METHOD=delete \
    \
    DEFENDER_SERVER_SECURITY_MANAGER_HOST=manager \
    DEFENDER_SERVER_SECURITY_ENABLE=true \
    DEFENDER_SERVER_SECURITY_USERNAME=admin \
    DEFENDER_SERVER_SECURITY_PASSWORD=iknowwhour \
    DEFENDER_SERVER_SECURITY_MASK_ENABLE=true \
    DEFENDER_SERVER_SECURITY_MASK_TYPE=html \
    DEFENDER_SERVER_SECURITY_MASK_HTML=public/404.html \
    DEFENDER_SERVER_SECURITY_MASK_JSON=public/404.json \
    \
    DEFENDER_SERVER_LOG_CONSOLE_ENABLE=true \
    DEFENDER_SERVER_LOG_CONSOLE_TYPE=json \
    DEFENDER_SERVER_LOG_CONSOLE_SEPARATOR=@ \
    DEFENDER_SERVER_LOG_FILE_ENABLE=false \
    DEFENDER_SERVER_LOG_FILE_NAME=history/defender.log \
    DEFENDER_SERVER_LOG_FILE_TYPE=default \
    DEFENDER_SERVER_LOG_FILE_SEPARATOR=@ \
    \
    DEFENDER_SERVER_STORAGE_TYPE="redis" \
    DEFENDER_SERVER_STORAGE_REDIS_HOST=redis \
    DEFENDER_SERVER_STORAGE_REDIS_PORT=6379 \
    DEFENDER_SERVER_STORAGE_REDIS_PASSWORD=redis \
    DEFENDER_SERVER_STORAGE_REDIS_DATABASE=0 \
    \
    DEFENDER_PROXY_TLS_ENABLE=false \
    DEFENDER_PROXY_TLS_KEY=tls/server.key \
    DEFENDER_PROXY_TLS_CRT=tls/server.crt \
    DEFENDER_PROXY_HOST= \
    DEFENDER_PROXY_PORT=9948 \
    DEFENDER_PROXY_VIOLATION_SCORE=5 \
    DEFENDER_PROXY_VIOLATION_LEVEL=1 \
    DEFENDER_PROXY_SEVERITY_NOTICE=2 \
    DEFENDER_PROXY_SEVERITY_WARNING=3 \
    DEFENDER_PROXY_SEVERITY_ERROR=4 \
    DEFENDER_PROXY_SEVERITY_CRITICAL=5 \
    DEFENDER_PROXY_HISTORY_AUDIT_PATH=history/audit \
    DEFENDER_PROXY_HISTORY_ERROR_ENABLE=true \
    DEFENDER_PROXY_HISTORY_ERROR_PATH=history/error \
    \
    DEFENDER_PROXY_BACKEND_SCHEME=http \
    DEFENDER_PROXY_BACKEND_HOST=backend \
    DEFENDER_PROXY_BACKEND_PORT=80 \
    DEFENDER_PROXY_BACKEND_PATH= \
    \
    DEFENDER_PROXY_REPORT_API_PATH=api/v1/reports/create \
    DEFENDER_PROXY_REPORT_API_HEADER="X-Manager-Token" \
    DEFENDER_PROXY_REPORT_API_TOKEN= \
    DEFENDER_PROXY_REPORT_AUTH_USERNAME= \
    DEFENDER_PROXY_REPORT_AUTH_PASSWORD=

ENTRYPOINT [ "./madsecurity.defender" ]
