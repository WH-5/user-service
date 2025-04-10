#!/bin/sh
set -e

echo "Waiting for database to be ready..."

while ! nc -z database 5432; do
  sleep 1
done

while ! nc -z redis 6379; do
  sleep 1
done

echo "Database is ready. Starting the service..."
exec "$@"