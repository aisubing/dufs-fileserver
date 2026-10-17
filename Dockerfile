FROM --platform=linux/amd64 messense/rust-musl-cross:x86_64-musl AS amd64
ARG DUFS_BUILD_ID=""
ENV DUFS_BUILD_ID=${DUFS_BUILD_ID}
COPY . .
RUN cargo install --path . --root /

FROM --platform=linux/amd64 messense/rust-musl-cross:aarch64-musl AS arm64
ARG DUFS_BUILD_ID=""
ENV DUFS_BUILD_ID=${DUFS_BUILD_ID}
COPY . .
RUN cargo install --path . --root /

FROM ${TARGETARCH} AS builder

FROM scratch
COPY --from=builder /bin/dufs /bin/dufs
STOPSIGNAL SIGINT

# 让 Docker 面板（飞牛 / Portainer / 群晖 / 1Panel）能自动识别端口与存储映射
EXPOSE 5000
VOLUME /data
WORKDIR /data

ENTRYPOINT ["/bin/dufs"]
# 配置与文件完全分离：/data/files 为分享根，/data/config 存管理员配置。
# 分享的文件放到 files/ 里，宿主机上整理文件不会碰到处在 config/ 的配置。
CMD ["/data/files", "--config-dir", "/data/config", "-A"]
