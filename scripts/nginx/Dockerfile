FROM nginx:latest

RUN apt-get update && apt-get install -y rsyslog && \
    rm -rf /var/lib/apt/lists/*

# Remove stdout/stderr symlinks, create real log files
RUN unlink /var/log/nginx/access.log && \
    unlink /var/log/nginx/error.log && \
    touch /var/log/nginx/access.log /var/log/nginx/error.log && \
    chown nginx:nginx /var/log/nginx/access.log /var/log/nginx/error.log

# Disable imklog (no /proc/kmsg access in Docker/WSL2)
RUN sed -i '/imklog/s/^/#/' /etc/rsyslog.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
