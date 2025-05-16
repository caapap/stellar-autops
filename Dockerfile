FROM docker.io/library/golang:1.22.3-alpine3.20 AS builder

WORKDIR /build
# 复制go.mod和go.sum文件
COPY go.mod go.sum ./
# 下载依赖
RUN go mod download
# 复制源代码
COPY . .
RUN go env -w GO111MODULE=on && \
    go mod tidy && \
    go build -mod=mod -o stellar-autops . && \
    ls -la /build

FROM docker.io/alpine:3.21.0
# 添加标识信息
LABEL version="1.0" \
      description="Prometheus Automated Inspection" \
      maintainer="caapap"
WORKDIR /app
COPY --from=builder /build/stellar-autops /app/
COPY --from=builder /build/config /app/config/
COPY --from=builder /build/outputs /app/outputs/
COPY --from=builder /build/reports /app/reports/
COPY --from=builder /build/templates /app/templates/
EXPOSE 8091
# 运行应用程序
CMD ["./stellar-autops", "-port", "8091"]