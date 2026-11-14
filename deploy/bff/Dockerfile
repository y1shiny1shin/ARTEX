FROM alpine:latest
RUN mkdir -p /data
COPY ryagent-bff /usr/local/bin/ryagent-bff
RUN chmod +x /usr/local/bin/ryagent-bff
EXPOSE 22250
ENTRYPOINT ["/usr/local/bin/ryagent-bff"]
