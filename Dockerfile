# syntax=docker/dockerfile:1.7
FROM node:26-bookworm-slim AS web-build
WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci
COPY angular.json tsconfig.json tsconfig.app.json .postcssrc.json ./
COPY public ./public
COPY src ./src
RUN npm run build

FROM debian:bookworm-slim AS pocketbase-download
ARG POCKETBASE_VERSION=0.40.2
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip \
  && rm -rf /var/lib/apt/lists/*
RUN arch="$TARGETARCH" \
  && case "$arch" in amd64|arm64) ;; *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; esac \
  && curl --fail --silent --show-error --location \
    "https://github.com/pocketbase/pocketbase/releases/download/v${POCKETBASE_VERSION}/pocketbase_${POCKETBASE_VERSION}_linux_${arch}.zip" \
    --output /tmp/pocketbase.zip \
  && unzip /tmp/pocketbase.zip -d /out \
  && chmod +x /out/pocketbase

FROM oven/bun:1.4.0-debian AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl nginx tini \
  && rm -rf /var/lib/apt/lists/* /etc/nginx/sites-enabled/default
WORKDIR /app
ENV NODE_ENV=production \
    POCKETBASE_URL=http://127.0.0.1:8090 \
    POCKETBASE_DATA_DIR=/data \
    OLLAMA_MODEL=glm-5.3-flash:cloud \
    SCAN_POLL_MS=4000
COPY --from=pocketbase-download /out/pocketbase /usr/local/bin/pocketbase
COPY --from=web-build /build/dist/wellguard-observe/browser /usr/share/nginx/html
COPY --from=web-build /build/node_modules ./node_modules
COPY package.json ./
COPY agent ./agent
COPY scripts ./scripts
COPY pocketbase/pb_migrations ./pb_migrations
COPY deploy/nginx.conf /etc/nginx/nginx.conf
COPY deploy/start.sh /usr/local/bin/wellguard-start
RUN chmod +x /usr/local/bin/wellguard-start && mkdir -p /data && chown -R bun:bun /data /app /usr/share/nginx/html
USER bun
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD curl --fail --silent http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/local/bin/wellguard-start"]
