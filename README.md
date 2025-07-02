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

บางทีมันโหลดไม่ติดเช็คดีๆนะ โหลดแบบ pip install เลยก็ได้

4.ตั้งค่า Django ให้ใช้ PyMySQL แทน mysqlclient

 เปิดไฟล์: yourproject/__init__.py
 
(คือไฟล์ในโฟลเดอร์โปรเจกต์ที่มี settings.py)

เพิ่มบรรทัดนี้เข้าไปด้านบนสุด:

import pymysql

pymysql.install_as_MySQLdb()

และตรวจสอบ / แก้ไขไฟล์ settings.py

5. สร้างฐานข้อมูลใน MySQL
ชื่อ root 

รหัส 12345  ตรวจสอบดีๆแต่ละเครื่องรหัสไม่เหมือนกัน 

พอต 3066

ชื่อ databast (คำสั่ง)
mysql -u root -p

12345

CREATE DATABASE mydata85 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

![image](https://github.com/user-attachments/assets/3800684e-f3e7-4e89-96c7-5065f7ac1180)


6.รันคำสั่ง Migrations และ Start Server\

อย่าลืมลบ C:\Users\Apai\Desktop\projectgenni\Project--topics-in-DSSI\notifications\migrations 

C:\Users\Apai\Desktop\projectgenni\Project--topics-in-DSSI\myapp\migrations
![image](https://github.com/user-attachments/assets/807f2497-23bf-4412-ab8f-876009d7d1ee)
![image](https://github.com/user-attachments/assets/f7a8fbe1-4c87-4a89-a42e-afe6be0a43cb)

มีสองที่นะ โปรต้องทำ noticแยก   ลบพวก 0001 0002 ออก ค่อย make 

C:\Users\Apai\Desktop\projectgenni\Project--topics-in-DSSI\myapp\migrations\0001_initial.py
python manage.py makemigrations

python manage.py migrate


python manage.py runserver

จากนั้นเปิดเบราว์เซอร์แล้วเข้า:

http://127.0.0.1:8000/

ภาพและโลโก้ต่างๆไม่มีไม่เป็นไรเพราะ เจนเอาออกเนื่องจากไฟล์ใหญ่ ไม่สามารถอัพขึ้นกิตได้
