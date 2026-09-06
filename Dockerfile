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

FROM debian:bookworm-slim AS nuclei-download
ARG NUCLEI_VERSION=3.11.1
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip \
  && rm -rf /var/lib/apt/lists/*
RUN arch="$TARGETARCH" \
  && case "$arch" in amd64|arm64) ;; *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; esac \
  && archive="nuclei_${NUCLEI_VERSION}_linux_${arch}.zip" \
  && curl --fail --silent --show-error --location \
    "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/${archive}" --output "/tmp/${archive}" \
  && curl --fail --silent --show-error --location \
    "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_checksums.txt" --output /tmp/nuclei-checksums.txt \
  && cd /tmp \
  && grep "  ${archive}$" nuclei-checksums.txt | sha256sum --check - \
  && unzip "${archive}" nuclei -d /out \
  && chmod +x /out/nuclei

FROM oven/bun:1.4.0-debian AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl gosu nginx tini chromium \
  && rm -rf /var/lib/apt/lists/* /etc/nginx/sites-enabled/default
WORKDIR /app
ENV NODE_ENV=production \
    POCKETBASE_URL=http://127.0.0.1:8090 \
    POCKETBASE_DATA_DIR=/data \
    OLLAMA_MODEL=glm-5.3:cloud \
    OLLAMA_REASONING_EFFORT=high \
    WELLGUARD_NUCLEI_TEMPLATES=/app/nuclei/templates \
    SCAN_POLL_MS=4000 \
    SCHEDULE_POLL_MS=60000 \
    OBSERVER_CHROMIUM_PATH=/usr/bin/chromium
COPY --from=pocketbase-download /out/pocketbase /usr/local/bin/pocketbase
COPY --from=nuclei-download /out/nuclei /usr/local/bin/nuclei
COPY --from=web-build /build/dist/wellguard-observe/browser /usr/share/nginx/html
COPY --from=web-build /build/node_modules ./node_modules
COPY package.json ./
COPY agent ./agent
COPY nuclei ./nuclei
COPY scripts ./scripts
COPY pocketbase/pb_migrations ./pb_migrations
COPY deploy/nginx.conf /etc/nginx/nginx.conf
COPY --chmod=755 deploy/start.sh /usr/local/bin/wellguard-start
RUN mkdir -p /data && chown bun:bun /data
EXPOSE 8080
VOLUME ["/data"]
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/local/bin/wellguard-start"]
