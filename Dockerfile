FROM python:3.10

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY wait-for-it.sh .
RUN chmod +x wait-for-it.sh

COPY . .

# เพิ่ม pymysql ให้ Django ใช้แทน mysqlclient
RUN echo "import pymysql; pymysql.install_as_MySQLdb()" >> project/__init__.py

