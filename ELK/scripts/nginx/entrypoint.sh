#!/bin/bash
set -e

# Fix symlinks that the volume mount may restore
# This runs AFTER volumes are mounted, so it's guaranteed to work
for f in /var/log/nginx/access.log /var/log/nginx/error.log; do
    if [ -L "$f" ]; then
        unlink "$f"
        touch "$f"
        chown nginx:nginx "$f"
    fi
done

# Start rsyslog in background
rsyslogd

# Start nginx in foreground
exec nginx -g "daemon off;"