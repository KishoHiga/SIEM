# SentinelCore — образ «запустил и работает»:
#   docker run -d -p 8080:8080 -v sentinel-data:/data ghcr.io/kishohiga/siem
# Панель: http://localhost:8080. Ключ входа — переменная SENTINEL_ADMIN_KEY или строка в логе контейнера.

ARG NODE_IMAGE=node:22-bookworm-slim
ARG BASE_IMAGE=ubuntu:24.04

# 1. Панель (React) — статические файлы
FROM ${NODE_IMAGE} AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN --mount=type=secret,id=proxy_ca,required=false \
    if [ -f /run/secrets/proxy_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/proxy_ca; fi; \
    npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# 2. Сервер и агент (C++)
FROM ${BASE_IMAGE} AS build
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends g++ cmake make libssl-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY CMakeLists.txt ./
COPY src src
COPY tools tools
COPY tests tests
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
 && cmake --build build -j"$(nproc)" --target sentinel-server sentinel-agent \
 && strip build/sentinel-server build/sentinel-agent

# 3. Итоговый образ: только программа, панель и правила
FROM ${BASE_IMAGE}
ARG VERSION=dev
LABEL org.opencontainers.image.title="SentinelCore" \
      org.opencontainers.image.description="SIEM: сбор логов, обнаружение атак, инциденты, блокировки" \
      org.opencontainers.image.source="https://github.com/KishoHiga/SIEM" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="NOASSERTION"
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libssl3t64 ca-certificates tzdata \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 sentinel \
 && useradd --system --uid 10001 --gid 10001 --home-dir /data --no-create-home --shell /usr/sbin/nologin sentinel \
 && mkdir -p /data && chown sentinel:sentinel /data
COPY --from=build /src/build/sentinel-server /src/build/sentinel-agent /usr/local/bin/
COPY --from=web /src/web/dist /usr/share/sentinel/web
COPY rules /usr/share/sentinel/rules
COPY docker/sentinel.yaml /etc/sentinel/sentinel.yaml
COPY docker/entrypoint.sh /usr/local/bin/sentinel-entrypoint
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["sentinel-server", "healthcheck", "-c", "/etc/sentinel/sentinel.yaml"]
ENTRYPOINT ["sentinel-entrypoint"]
CMD ["run"]
