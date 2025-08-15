#!/usr/bin/env bash
set -e

echo "⏳ Waiting for MySQL at $MYSQL_HOST:$MYSQL_PORT..."
for i in {1..60}; do
  nc -z $MYSQL_HOST $MYSQL_PORT && break
  echo "... retry $i"
  sleep 1
done

echo "✅ MySQL is ready. Running migrations & collectstatic..."

python manage.py migrate --noinput
python manage.py collectstatic --noinput

exec gunicorn project.wsgi:application --bind 0.0.0.0:8080 --workers 3
