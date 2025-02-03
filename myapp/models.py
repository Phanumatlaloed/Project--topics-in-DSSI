from django.conf import settings
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
import uuid
import os

class CustomUserManager(BaseUserManager):
    """ Manager สำหรับ CustomUser """

    def create_user(self, username, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Users must have an email address")
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        """สร้าง Superuser"""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("role", "admin")  # ให้ Superuser เป็นแอดมินโดยอัตโนมัติ

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(username, email, password, **extra_fields)


class CustomUser(AbstractUser):
    """ โมเดล User แบบกำหนดเอง """
    ROLE_CHOICES = (
        ('user', 'User'),
        ('member', 'Member'),
        ('seller', 'Seller'),
        ('admin', 'Admin'),
    )
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')

    def is_seller(self):
        return self.role == 'seller'

    def is_member(self):
        return self.role == 'member'

    def is_admin(self):
        return self.role == 'admin'

class Member(models.Model):
    """ โมเดลสมาชิกทั่วไป """
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='member_profile')  # ✅ ใช้ member_profile
    profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)
    gender = models.CharField(max_length=10, choices=[('male', 'Male'), ('female', 'Female'), ('other', 'Other')])
    date_of_birth = models.DateField()

    def __str__(self):
        return self.user.username


class UserProfile(models.Model):
    """ โปรไฟล์ผู้ใช้ทั่วไป """
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='user_profile')
    profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)

    def __str__(self):
        return self.user.username
    
from django.db import models
from django.conf import settings

import uuid
from django.db import models
from django.conf import settings

def upload_to(instance, filename):
    """ กำหนด path การอัปโหลดไฟล์แยกตามประเภท (รูป & วิดีโอ) และเปลี่ยนชื่อไฟล์ให้ไม่ซ้ำ """
    folder = "images" if instance.media_type == "image" else "videos"
    ext = filename.split('.')[-1]  # ดึงนามสกุลไฟล์ เช่น .jpg, .mp4
    unique_filename = f"{uuid.uuid4()}.{ext}"  # ใช้ UUID4 เป็นชื่อไฟล์
    return os.path.join(f"posts/{folder}/", unique_filename)

class Post(models.Model):
    """ โมเดลโพสต์ทั่วไป """
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='posts')
    content = models.TextField(blank=True, null=True, default="")
    likes = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name='liked_posts', blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    shared_from = models.ForeignKey(
        'self', on_delete=models.SET_NULL, null=True, blank=True, related_name='shared_by'
    )

    class Meta:
        ordering = ['-created_at']
        verbose_name_plural = "Posts"

    def __str__(self):
        return f"{self.user.username}: {self.content[:20] if self.content else 'No content'}"

class PostMedia(models.Model):
    """ โมเดลเก็บไฟล์รูปภาพและวิดีโอของโพสต์ """
    MEDIA_TYPE_CHOICES = (
        ('image', 'Image'),
        ('video', 'Video'),
    )
    
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="media")
    file = models.FileField(upload_to=upload_to)  # ใช้ฟังก์ชันอัปโหลดแยกตามประเภทไฟล์
    media_type = models.CharField(max_length=10, choices=MEDIA_TYPE_CHOICES)
    caption = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at']
        verbose_name_plural = "Post Media"

    def __str__(self):
        return f"({self.media_type.upper()}) {os.path.basename(self.file.name)} for Post {self.post.id}"


class SavedPost(models.Model):
    """ โมเดลสำหรับบันทึกโพสต์ที่ชื่นชอบ """
    user = models.ForeignKey(Member, on_delete=models.CASCADE, related_name='saved_posts')
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='saves')
    saved_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.user.username} saved Post {self.post.id}"


class Comment(models.Model):
    """ โมเดลสำหรับคอมเมนต์โพสต์ """
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='comments')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} on {self.post.id}: {self.content[:20]}"


class CommunityGroup(models.Model):
    """ โมเดลกลุ่มชุมชน """
    name = models.CharField(max_length=100)
    description = models.TextField()
    rules = models.TextField()
    image = models.ImageField(upload_to='groups/images/', blank=True, null=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='created_groups')
    members = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name='joined_groups', blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class GroupPost(models.Model):
    """ โมเดลโพสต์ในกลุ่ม """
    group = models.ForeignKey(CommunityGroup, on_delete=models.CASCADE, related_name='posts')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    content = models.TextField(blank=True, null=True)
    image = models.ImageField(upload_to='groups/posts/', blank=True, null=True)
    video = models.FileField(upload_to='groups/videos/', blank=True, null=True)
    likes = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name='liked_group_posts', blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    shared_from = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='shared_posts')

    def __str__(self):
        return f"{self.user.username} - {self.group.name}"


class GroupComment(models.Model):
    """ โมเดลคอมเมนต์ในโพสต์ของกลุ่ม """
    post = models.ForeignKey(GroupPost, on_delete=models.CASCADE, related_name='comments')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} on {self.post.id}: {self.content[:20]}"


class SavedGroupPost(models.Model):
    """ โมเดลสำหรับบันทึกโพสต์ของกลุ่ม """
    user = models.ForeignKey(Member, on_delete=models.CASCADE, related_name='saved_group_posts')
    post = models.ForeignKey(GroupPost, on_delete=models.CASCADE, related_name='saves')
    saved_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.user.username} saved GroupPost {self.post.id}"


class Seller(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='seller_profile')
    store_name = models.CharField(max_length=255)
    email = models.EmailField(unique=True, blank=False, null=False)  # ✅ เพิ่ม email
    store_image = models.ImageField(upload_to='store_images/', blank=True, null=True)
    contact_info = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.store_name




class Product(models.Model):
    """ โมเดลสินค้าในร้านค้า """
    seller = models.ForeignKey(Seller, on_delete=models.CASCADE, related_name='products')
    name = models.CharField(max_length=255)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    stock = models.PositiveIntegerField()
    image = models.ImageField(upload_to='products/')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name
