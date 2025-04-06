from django.conf import settings
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
import uuid
import os
from django.utils import timezone

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
    email = models.EmailField(unique=False)  # ✅ อีเมลสามารถซ้ำกันได้
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
    date_of_birth = models.DateField(null=True, blank=True)  # ✅ แก้ไขตรงนี้

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


from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()  # ✅ ดึงโมเดล User จากระบบ Auth อัตโนมัติ

class Post(models.Model):
    """ โมเดลโพสต์ทั่วไป """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="posts")  # ✅ เช็คตรงนี้
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='posts')
    content = models.TextField(blank=True, null=True, default="")
    likes = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name='liked_posts', blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_community_post = models.BooleanField(default=False)  # ✅ เพิ่มฟิลด์ระบุว่าเป็นโพสต์จาก Community หรือไม่
    shared_from = models.ForeignKey(
        'self', on_delete=models.SET_NULL, null=True, blank=True, related_name='shared_by'
    )
    is_reported = models.BooleanField(default=False)  # ✅ เพิ่มฟิลด์เพื่อซ่อนโพสต์ที่ถูกรายงาน


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
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='saved_posts')
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

BANK_CHOICES = [
    ('kbank', 'ธนาคารกสิกรไทย'),
    ('scb', 'ธนาคารไทยพาณิชย์'),
    ('bbl', 'ธนาคารกรุงเทพ'),
    ('ktb', 'ธนาคารกรุงไทย'),
    ('bay', 'ธนาคารกรุงศรีอยุธยา'),
    ('ttb', 'ธนาคารทหารไทยธนชาต'),
    ('gsb', 'ธนาคารออมสิน'),
    ('baac', 'ธ.ก.ส.'),
]
class Seller(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='seller_profile')
    store_name = models.CharField(max_length=255)
    email = models.EmailField(unique=True, blank=False, null=False)  # ✅ เพิ่ม email
    store_image = models.ImageField(upload_to='store_images/', blank=True, null=True)
    contact_info = models.TextField(blank=True, null=True)
    # ✅ เพิ่มเลขบัญชีและชื่อบัญชีธนาคาร
    bank_name = models.CharField(max_length=50, choices=BANK_CHOICES, blank=True, null=True)  # ✅ เปลี่ยนให้เลือกจาก dropdown
    bank_account_name = models.CharField(max_length=255, blank=True, null=True)  # ชื่อบัญชีธนาคาร
    bank_account_number = models.CharField(max_length=50, blank=True, null=True)  # เลขบัญชีธนาคาร
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.store_name




class Product(models.Model):
    """ โมเดลสินค้าในร้านค้า """
    CATEGORY_CHOICES = [
        ('makeup', 'เครื่องสำอาง (Makeup)'),
        ('skincare', 'สกินแคร์ (Skincare)'),
        ('haircare', 'ผลิตภัณฑ์ดูแลเส้นผม (Hair Care)'),
        ('bodycare', 'ผลิตภัณฑ์ดูแลร่างกาย (Body Care)'),
        ('nailcare', 'ผลิตภัณฑ์ดูแลเล็บ (Nail Care)'),
        ('wellness', 'ผลิตภัณฑ์ดูแลสุขภาพ (Wellness & Supplements)'),
        ('beautytools', 'อุปกรณ์เสริมความงาม (Beauty Tools)'),
    ]

    seller = models.ForeignKey('Seller', on_delete=models.CASCADE, related_name='products')
    name = models.CharField(max_length=255)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    stock = models.PositiveIntegerField(default=0)  # คงเหลือ
    total_sold = models.PositiveIntegerField(default=0)  # ✅ เพิ่มฟิลด์จำนวนที่ขายได้
    image = models.ImageField(upload_to='products/')
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES, default='makeup')  # ✅ หมวดหมู่สินค้า
    summary = models.TextField(blank=True, null=True)  # ✅ เพิ่มฟิลด์สรุปรีวิว
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class Cart(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)


class CartItem(models.Model):
    cart = models.ForeignKey(Cart, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1)

    def total_price(self):
        return self.quantity * self.product.price

class ShippingAddress(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="shipping_address")
    address = models.TextField()
    phone_number = models.CharField(max_length=15)
    city = models.CharField(max_length=100)
    postal_code = models.CharField(max_length=10)

    def __str__(self):
        return f"{self.address}, {self.city} ({self.postal_code})"
    

from django.db import models
from django.conf import settings

class Order(models.Model):
    STATUS_CHOICES = [
        ('pending', 'รอดำเนินการ'),
        ('shipped', 'จัดส่งแล้ว'),
        ('delivered', 'จัดส่งสำเร็จ'),
        ('refunded', 'ขอคืนเงิน'),
        ('cancelled', 'ยกเลิกแล้ว'),  # ✅ เพิ่มสถานะนี้
    ]
    
    PAYMENT_STATUS_CHOICES = [
        ('pending', 'รอการชำระเงิน'),
        ('paid', 'ชำระเงินแล้ว'),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="orders")
    seller = models.ForeignKey('Seller', on_delete=models.SET_NULL, null=True, blank=True, related_name="orders")  
    shipping_address = models.TextField(default="กรุณากรอกที่อยู่จัดส่ง")  # ✅ แก้ไขตรงนี้
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)  # ✅ เพิ่มเมือง
    postal_code = models.CharField(max_length=10, blank=True, null=True)  # ✅ เพิ่มรหัสไปรษณีย์
    total_price = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    payment_status = models.CharField(max_length=20, choices=PAYMENT_STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(default=timezone.now)
    refund_proof = models.ImageField(upload_to='refund_proofs/', blank=True, null=True)


    def __str__(self):
        return f"Order {self.id} by {self.user.username}"

class Payment(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    slip = models.ImageField(upload_to='payment_slips/')
    created_at = models.DateTimeField(auto_now_add=True)

# ✅ แก้ไข Payment ให้รองรับค่า default ของ Order
class Payment(models.Model):
    """ โมเดลการชำระเงิน """
    order = models.OneToOneField(
        "Order",
        on_delete=models.CASCADE,
        related_name="payment",
        default=1  # ✅ หรือใช้ `SET_DEFAULT` ถ้าระบบมี order อยู่แล้ว
    )
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    slip = models.ImageField(upload_to='payment_slips/', blank=True, null=True)  # ✅ ให้ slip nullable ชั่วคราว
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Payment for Order {self.order.id} - {self.user.username}"

from django.core.exceptions import ObjectDoesNotExist

def get_default_seller():
    from .models import Seller
    seller = Seller.objects.first()
    return seller.id if seller else None  # ✅ คืนค่า None แทนการ error

class OrderItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name="order_items")
    product = models.ForeignKey('Product', on_delete=models.CASCADE)
    seller = models.ForeignKey('Seller', on_delete=models.CASCADE, related_name="order_items", default=get_default_seller)  # ✅ แก้ไขตรงนี้
    quantity = models.PositiveIntegerField()
    price_per_item = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)

    def get_total_price(self):
        return self.quantity * self.price_per_item



class Follow(models.Model):
    follower = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="following")
    following = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="followers")
    created_at = models.DateTimeField(auto_now_add=True)


    class Meta:
        unique_together = ("follower", "following")  # ป้องกันการติดตามซ้ำ

    def __str__(self):
        return f"{self.follower.username} follows {self.following.username}"
    
class GroupPostMedia(models.Model):
    MEDIA_TYPE_CHOICES = (
        ('image', 'Image'),
        ('video', 'Video'),
    )
    
    post = models.ForeignKey(GroupPost, on_delete=models.CASCADE, related_name="media")
    file = models.FileField(upload_to="group_posts/")  # ✅ กำหนด path ให้เก็บรูป  # ใช้ฟังก์ชันอัปโหลดเดิม
    media_type = models.CharField(max_length=10, choices=MEDIA_TYPE_CHOICES)
    caption = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at']
        verbose_name_plural = "Group Post Media"

    def __str__(self):
        return f"({self.media_type.upper()}) {os.path.basename(self.file.name)} for GroupPost {self.post.id}"
    

class Report(models.Model):
    REASON_CHOICES = [
        ('spam', 'Spam'),
        ('violence', 'Violence or Harmful Content'),
        ('harassment', 'Harassment or Bullying'),
        ('other', 'Other'),
    ]
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='reports')
    reported_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE)  # ✅ ใช้ CustomUser
    reason = models.CharField(max_length=20, choices=REASON_CHOICES)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Report by {self.reported_by.username} on Post {self.post.id}"

# Model สำหรับบล็อคผู้ใช้
class BlockedUser(models.Model):
    blocked_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='blocked_users')
    blocked_user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='blocked_by_users')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.blocked_by.username} blocked {self.blocked_user.username}"

# 🌟 รีวิวสินค้า (Review)
def review_media_upload_path(instance, filename):
    """ กำหนด path การอัปโหลดไฟล์ รีวิวแยกประเภท (รูป & วิดีโอ) และเปลี่ยนชื่อไฟล์ให้ไม่ซ้ำ """
    folder = "images" if instance.media_type == "image" else "videos"
    ext = filename.split('.')[-1]  
    unique_filename = f"{uuid.uuid4()}.{ext}"
    return os.path.join(f"reviews/{folder}/", unique_filename)


class Review(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name="reviews")
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name="reviews", null=True, blank=True)  # ✅ รองรับค่า NULL ชั่วคราว
    rating = models.IntegerField(choices=[(i, f"⭐ {i}") for i in range(1, 6)])  
    comment = models.TextField()
    sentiment = models.CharField(max_length=10, choices=[
        ('positive', 'Positive'),
        ('neutral', 'Neutral'),
        ('negative', 'Negative')
    ], default='neutral')  # ✅ เพิ่ม sentiment
    analysis_done = models.BooleanField(default=False)  # ✅ ต้องเพิ่ม field นี้
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        # ป้องกันการรีวิวซ้ำ
        unique_together = ('user', 'product', 'order')

    def __str__(self):
        return f"{self.user.username} - {self.product.name} ({self.rating} ⭐)"




class ReviewMedia(models.Model):
    """ โมเดลสำหรับเก็บไฟล์รีวิว (รูป & วิดีโอ) """
    MEDIA_TYPE_CHOICES = (
        ('image', 'Image'),
        ('video', 'Video'),
    )
    
    review = models.ForeignKey(Review, on_delete=models.CASCADE, related_name="media")
    file = models.FileField(upload_to=review_media_upload_path)  
    media_type = models.CharField(max_length=10, choices=MEDIA_TYPE_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at']

    def __str__(self):
        return f"({self.media_type.upper()}) {os.path.basename(self.file.name)}"
    
class ReviewResponse(models.Model):
    review = models.OneToOneField(Review, on_delete=models.CASCADE, related_name="response")  # One review gets one response
    seller = models.ForeignKey(Seller, on_delete=models.CASCADE)  # Ensure only the product's seller can respond
    response_text = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Response by {self.seller.store_name} to Review {self.review.id}"


from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver

class SellerWallet(models.Model):
    """ กระเป๋าเงินของผู้ขาย """
    seller = models.OneToOneField('Seller', on_delete=models.CASCADE, related_name='wallet')
    balance = models.DecimalField(max_digits=12, decimal_places=2, default=0.00)  # ยอดเงินในกระเป๋า
    last_withdrawn_amount = models.DecimalField(default=0.00, max_digits=10, decimal_places=2)  # ✅ เก็บยอดเงินที่ถอนในรอบล่าสุด
    last_withdrawal_time = models.DateTimeField(null=True, blank=True)
    last_withdrawn_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)  # อัปเดตล่าสุด

    def withdraw(self, amount):
        """ ถอนเงินออกจากกระเป๋าเงิน """
        if self.balance >= amount:
            self.balance -= amount
            self.save()
            return True
        return False  # ถอนเงินไม่สำเร็จ

    def __str__(self):
        return f"Wallet of {self.seller.store_name}: ฿{self.balance}"
    

@receiver(post_save, sender=Seller)
def create_or_update_seller_wallet(sender, instance, created, **kwargs):
    """ สร้างกระเป๋าเงินเมื่อผู้ขายถูกสร้าง หรืออัปเดตเมื่อผู้ขายมีอยู่แล้ว """
    if created:
        SellerWallet.objects.create(seller=instance)
    else:
        instance.wallet.save()  # อัปเดต timestamp ถ้ามีการเปลี่ยนแปลง

class WithdrawalRequest(models.Model):
    STATUS_CHOICES = [
        ("pending", "รอดำเนินการ"),
        ("approved", "อนุมัติแล้ว"),
        ("rejected", "ถูกปฏิเสธ"),
        ("paid", "โอนเงินแล้ว"),  # ✅ เพิ่มสถานะใหม่
    ]

    seller = models.ForeignKey('Seller', on_delete=models.CASCADE, related_name="withdraw_requests")
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=20, choices=[('pending', 'Pending'), ('approved', 'Approved'), ('rejected', 'Rejected')])
    created_at = models.DateTimeField(auto_now_add=True)

    # ✅ แอดมินอัปโหลดสลิปโอนเงิน
    payment_proof = models.ImageField(upload_to="withdraw_proofs/", blank=True, null=True)

    # ✅ ผู้ขายกดยืนยันว่าได้รับเงินแล้ว
    confirmed_by_seller = models.BooleanField(default=False)

    def approve(self):
        """ อนุมัติคำขอถอนเงิน """
        if self.status == "pending":
            self.status = "approved"
            self.save()

    def mark_paid(self, proof):
        """ แอดมินอัปโหลดสลิปเมื่อโอนเงินแล้ว """
        if self.status == "approved":
            self.status = "paid"
            self.payment_proof = proof
            self.save()

    def confirm_received(self):
        """ ผู้ขายกดยืนยันว่าได้รับเงินแล้ว """
        if self.status == "paid":
            self.confirmed_by_seller = True
            self.save()

    def __str__(self):
        return f"Withdrawal Request of {self.seller.store_name} - ฿{self.amount}"



class RefundRequest(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name="refund_requests")
    item = models.ForeignKey(OrderItem, on_delete=models.CASCADE, related_name="refund_requests", null=True, blank=True)  # ✅ สามารถคืนสินค้าเป็นรายชิ้นได้
    bank_name = models.CharField(max_length=100, blank=True, null=True)  # ✅ เพิ่มฟิลด์นี้
    account_number = models.CharField(max_length=50, blank=True, null=True)  # ✅ เพิ่มฟิลด์นี้
    account_name = models.CharField(max_length=100, blank=True, null=True)  # ✅ เพิ่มฟิลด์นี้
    refund_reason = models.TextField()
    payment_proof = models.ImageField(upload_to="payment_proof/", blank=True, null=True)
    refund_proof = models.ImageField(upload_to="refund_proofs/", blank=True, null=True)  # ✅ เพิ่มฟิลด์สำหรับแนบสลิปคืนเงิน
    return_item_proof = models.ImageField(upload_to="return_item_proofs/", blank=True, null=True)  # ✅ หลักฐานสินค้าที่ส่งคืน
    created_at = models.DateTimeField(auto_now_add=True)

    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("approved", "Approved"),
        ("refunded", "Refunded"),  # ✅ ผู้ขายโอนเงินคืนแล้ว
        ("rejected", "Rejected"),
    ]
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    confirmed_by_user = models.BooleanField(default=False)  # ✅ เพิ่มฟิลด์ให้ผู้ใช้กดยืนยัน

    def __str__(self):
        return f"Refund Request for {self.item.product.name if self.item else 'Unknown Item'} in Order #{self.order.id}"

from django.db import models
from django.contrib.auth import get_user_model
User = get_user_model()

class SellerNotification(models.Model):
    seller = models.ForeignKey(User, on_delete=models.CASCADE, related_name="seller_notifications")
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    def __str__(self):
        return f"📢 {self.seller.username} - {self.message[:50]}"

from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class MemberNotification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="member_notifications")
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    is_read = models.BooleanField(default=False)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"📢 {self.user.username} - {self.message[:50]}"
