FROM ubuntu/squid:latest

RUN apt-get update && apt-get install -y rsyslog && \
    rm -f /etc/squid/conf.d/rock.conf && \
    rm -f /etc/squid/conf.d/debian.conf && \
    mkdir -p /var/log /var/spool/squid && \
    touch /var/log/auth.log /var/log/syslog && \
    rm -rf /var/lib/apt/lists/*

COPY squid.conf /etc/squid/squid.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Override base image entrypoint completely
ENTRYPOINT ["/entrypoint.sh"]