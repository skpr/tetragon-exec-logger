FROM scratch

COPY --from=alpine:latest /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

COPY skpr-tetragon-exec-logger /usr/local/bin/skpr-tetragon-exec-logger

CMD ["skpr-tetragon-exec-logger"]