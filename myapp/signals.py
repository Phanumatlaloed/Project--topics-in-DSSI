from django.db.models.signals import post_save, m2m_changed
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from .models import Post, Comment, Order, Follow, GroupPost
from notifications.utils import create_notification

User = get_user_model()  # ✅ ใช้ CustomUser แทน auth.User

@receiver(post_save, sender=Post)
def new_post_notification(sender, instance, created, **kwargs):
    if created and sender == Post:  # ✅ ตรวจสอบว่า sender เป็น Post
        followers = Follow.objects.filter(following=instance.user)
        for follower in followers:
            create_notification(
                user=follower.follower,
                sender=instance.user,
                notification_type="new_post",
                post=instance
            )

# ✅ แจ้งเตือนเมื่อมีการคอมเมนต์โพสต์
@receiver(post_save, sender=Comment)
def new_comment_notification(sender, instance, created, **kwargs):
    if created and sender == Comment:  # ✅ ตรวจสอบว่า sender เป็น Comment
        create_notification(
            user=instance.post.user,
            sender=instance.user,
            notification_type="new_comment",
            post=instance.post
        )

# ✅ แจ้งเตือนเมื่อมีคำสั่งซื้อใหม่
@receiver(post_save, sender=Order)
def new_order_notification(sender, instance, created, **kwargs):
    if created:
        create_notification(
            user=instance.seller.user,
            sender=instance.user,
            notification_type="new_order",
            order=instance
        )

@receiver(m2m_changed, sender=GroupPost.likes.through)
def group_post_like_notification(sender, instance, action, pk_set, **kwargs):
    """ แจ้งเตือนเมื่อมีคนกดไลค์โพสต์ในกลุ่ม """
    if action == "post_add":  # ✅ ตรวจสอบว่าเป็นการเพิ่ม Like
        for user_id in pk_set:
            user = User.objects.get(id=user_id)  # ✅ ดึง Object User จาก ID
            create_notification(
                user=instance.user,  # ✅ แจ้งเตือนเจ้าของโพสต์
                sender=user,  # ✅ ส่ง Object `User` ไม่ใช่ `id`
                notification_type="like_group_post",
                post=None,  # ✅ ไม่ส่ง `post`
                group_post=instance  # ✅ ส่ง `group_post`
            )

@receiver(m2m_changed, sender=Post.likes.through)
def post_like_notification(sender, instance, action, pk_set, **kwargs):
    """ แจ้งเตือนเมื่อมีคนกดไลค์โพสต์ """
    if action == "post_add":  # ตรวจสอบว่าเป็นการเพิ่ม Like
        for user_id in pk_set:
            user = User.objects.get(id=user_id)
            create_notification(
                user=instance.user,  # เจ้าของโพสต์
                sender=user,  # คนที่กดไลค์
                notification_type="like_post",
                post=instance
            )

from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from .models import Member

@receiver(post_save, sender=User)
def create_member_profile(sender, instance, created, **kwargs):
    if created:
        Member.objects.create(user=instance)
