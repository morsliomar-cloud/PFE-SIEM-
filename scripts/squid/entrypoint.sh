#!/bin/sh
set -e

# No cache_dir configured, so no -z init needed
# Just remove any stale PID from a previous run
rm -f /run/squid.pid

exec squid -N