FROM python:3.10

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY wait-for-it.sh ./
RUN chmod +x wait-for-it.sh

COPY . .

# ใช้ pymysql แทน mysqlclient
RUN echo "import pymysql; pymysql.install_as_MySQLdb()" >> project/__init__.py

# ตั้งค่าคำสั่งที่ต้องการให้รันเมื่อคอนเทนเนอร์เริ่ม
CMD ["sh", "-c", "./wait-for-it.sh db:3306 --timeout=60 --strict -- python manage.py makemigrations && python manage.py migrate && python manage.py runserver 0.0.0.0:8000"]
