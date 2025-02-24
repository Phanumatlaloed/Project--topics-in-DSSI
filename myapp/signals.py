from django.db.models.signals import post_save, m2m_changed
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from .models import Post, Comment, Order, Follow, GroupPost, Member,CustomUser, Member

from notifications.utils import create_notification

# ✅ ใช้ CustomUser แทน `auth.User`
User = get_user_model()

# ✅ แจ้งเตือนเมื่อมีโพสต์ใหม่
@receiver(post_save, sender=Post)
def new_post_notification(sender, instance, created, **kwargs):
    if created:
        followers = Follow.objects.filter(following=instance.user)
        for follower in followers:
            create_notification(
                user=follower.follower,
                sender=instance.user,
                notification_type="new_post",
                post=instance
            )

# ✅ แจ้งเตือนเมื่อมีคอมเมนต์ใหม่ในโพสต์
@receiver(post_save, sender=Comment)
def new_comment_notification(sender, instance, created, **kwargs):
    if created:
        create_notification(
            user=instance.post.user,
            sender=instance.user,
            notification_type="new_comment",
            post=instance.post
        )

# ✅ แจ้งเตือนเมื่อมีการสั่งซื้อใหม่
@receiver(post_save, sender=Order)
def new_order_notification(sender, instance, created, **kwargs):
    if created:
        create_notification(
            user=instance.seller.user,
            sender=instance.user,
            notification_type="new_order",
            order=instance
        )

# ✅ แจ้งเตือนเมื่อมีคนกดไลค์โพสต์ในกลุ่ม
@receiver(m2m_changed, sender=GroupPost.likes.through)
def group_post_like_notification(sender, instance, action, pk_set, **kwargs):
    if action == "post_add":
        for user_id in pk_set:
            try:
                user = User.objects.get(id=user_id)  # ✅ ใช้ CustomUser
                create_notification(
                    user=instance.user,
                    sender=user,
                    notification_type="like_group_post",
                    post=None,
                    group_post=instance
                )
            except User.DoesNotExist:
                print(f"❌ Error: User with id {user_id} does not exist.")

# ✅ แจ้งเตือนเมื่อมีคนกดไลค์โพสต์ทั่วไป
@receiver(m2m_changed, sender=Post.likes.through)
def post_like_notification(sender, instance, action, pk_set, **kwargs):
    if action == "post_add":
        for user_id in pk_set:
            try:
                user = User.objects.get(id=user_id)  # ✅ ใช้ CustomUser
                create_notification(
                    user=instance.user,
                    sender=user,
                    notification_type="like_post",
                    post=instance
                )
            except User.DoesNotExist:
                print(f"❌ Error: User with id {user_id} does not exist.")

@receiver(post_save, sender=CustomUser)
def create_member_profile(sender, instance, created, **kwargs):
    if created:
        # ✅ ตรวจสอบก่อนว่าสร้าง `Member` ซ้ำหรือไม่
        if not Member.objects.filter(user=instance).exists():
            Member.objects.create(user=instance)
