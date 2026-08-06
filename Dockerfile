FROM node:22-alpine AS frontend-builder

WORKDIR /src/frontend
RUN corepack enable
COPY frontend/package.json frontend/pnpm-lock.yaml frontend/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY frontend/ ./
RUN pnpm build

FROM golang:1.24-alpine AS go-builder

RUN apk add --no-cache ca-certificates git tzdata
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend-builder /src/frontend/dist ./frontend/dist
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-w -s" -o /out/bindCacheAnalyze .

FROM alpine:3.22

RUN apk add --no-cache ca-certificates tzdata \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
WORKDIR /app
COPY --from=go-builder /out/bindCacheAnalyze /usr/local/bin/bindCacheAnalyze

EXPOSE 8888
ENTRYPOINT ["/usr/local/bin/bindCacheAnalyze"]
CMD ["-web-db", "-config", "/etc/bind-cache-analyze/config.json"]
