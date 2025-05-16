FROM docker.io/library/alpine:3.21.0
# 添加标识信息
LABEL version="1.0" \
      description="Prometheus Automated Inspection" \
      maintainer="caapap"
WORKDIR /app
COPY stellar-autops /app/
COPY config /app/config/
COPY outputs /app/outputs/
COPY reports /app/reports/
COPY templates /app/templates/
EXPOSE 8091
# 运行应用程序
CMD ["./stellar-autops", "-port", "8091"]