# projectend
# webgenni

# วิธีการดาวโหลด
1.เตรียม Python และ MySQL

โหลดpython และ Mysql

https://www.python.org/downloads/

https://dev.mysql.com/downloads/installer/

2.Clone โปรเจกต์จาก GitHub

cd C:\Users\<ชื่อคุณ>\Desktop (สร้างเพื่อเก็บงาน)

git clone https://github.com/Phanumatlaloed/Project--topics-in-DSSI.git

cd Project--topics-in-DSSI

3. สร้าง Virtual Environment และติดตั้ง Dependencies

python -m venv venv

.\venv\Scripts\activate

pip install --upgrade pip

ติดตั้ง dependency ต่าง ๆ

pip install -r django.txt

หรือ pip install โหลดเอง 
python -m pip install Pillow,django,PyJWT,requests,mysqlclient,django-allauth,cryptography,Pillow,django-crispy-forms,python-dotenv
django-cors-headers,bootstrap,allauth,requests,jwt

4.ตั้งค่า Django ให้ใช้ PyMySQL แทน mysqlclient

 เปิดไฟล์: yourproject/__init__.py
 
(คือไฟล์ในโฟลเดอร์โปรเจกต์ที่มี settings.py)

เพิ่มบรรทัดนี้เข้าไปด้านบนสุด:

import pymysql

pymysql.install_as_MySQLdb()

และตรวจสอบ / แก้ไขไฟล์ settings.py

5. สร้างฐานข้อมูลใน MySQL
ชื่อ root 

รหัส 12345

พอต 3066

ชื่อ databast (คำสั่ง)
mysql -u root -p

12345

CREATE DATABASE mydata85 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

![image](https://github.com/user-attachments/assets/3800684e-f3e7-4e89-96c7-5065f7ac1180)


6.รันคำสั่ง Migrations และ Start Server

python manage.py makemigrations

python manage.py migrate

python manage.py createsuperuser  # สร้างแอดมินเข้าเว็บ

python manage.py runserver

จากนั้นเปิดเบราว์เซอร์แล้วเข้า:

http://127.0.0.1:8000/
