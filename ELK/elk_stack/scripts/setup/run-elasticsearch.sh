#!/bin/bash

# This script starts a single-node Elasticsearch container for development.

CONTAINER_NAME="es01"
ES_VERSION="9.1.3"

# Stop and remove any existing container with the same name
if [ "$(docker ps -a -q -f name=${CONTAINER_NAME})" ]; then
    echo "Stopping and removing existing '${CONTAINER_NAME}' container..."
    docker stop ${CONTAINER_NAME}
    docker rm ${CONTAINER_NAME}
fi

echo "Starting Elasticsearch container '${CONTAINER_NAME}'..."

docker run -d --name ${CONTAINER_NAME} \
  -p 9200:9200 \
  -p 9300:9300 \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" \
  docker.elastic.co/elasticsearch/elasticsearch-wolfi:${ES_VERSION}

echo "Elasticsearch container started."
echo "Wait a few moments for it to initialize, then you can verify it at http://localhost:9200"