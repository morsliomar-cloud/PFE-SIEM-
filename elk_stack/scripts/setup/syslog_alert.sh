#!/bin/bash

# Simple Syslog Test Script
HOST="localhost"
PORT="514"

echo "Sending simple syslog messages to $HOST:$PORT..."

# Send 10 simple test messages
for i in {1..10}; do
    # Use local system time in proper syslog format
    timestamp=$(date '+%b %d %H:%M:%S')
    
    # Simple syslog message format: <priority>timestamp hostname program: message
    message="<34>$timestamp testhost myapp: Simple test message number $i"
    
    echo "Sending: $message"
    echo "$message" | nc -u -w 1 $HOST $PORT
    
    sleep 1
done

echo ""
echo "Sent 10 test messages!"
echo "Waiting 5 seconds for processing..."
sleep 5

echo "Checking for today's index..."
today=$(date '+%Y.%m.%d')
curl -s "localhost:9200/_cat/indices/syslog-${today}?v"