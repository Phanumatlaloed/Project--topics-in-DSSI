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
from django.db.models.signals import post_save

from django.dispatch import receiver
from .models import Order, RefundRequest, SellerNotification, Review, WithdrawalRequest

# ✅ แจ้งเตือนผู้ขายเมื่อมีคำสั่งซื้อใหม่
from django.urls import reverse

from django.urls import reverse

@receiver(post_save, sender=Order)
def notify_seller_new_order(sender, instance, created, **kwargs):
    if created:
        order_url = reverse("seller_orders")  # ใช้ URL ของหน้าคำสั่งซื้อ
        message = f"🛒 คำสั่งซื้อใหม่ #{instance.id} ได้รับจาก {instance.user.username} <a href='{order_url}' class='notif-btn'>📜 ดูรายละเอียด</a>"

        SellerNotification.objects.create(
            seller=instance.seller.user,
            message=message
        )



# ✅ แจ้งเตือนผู้ขายเมื่อได้รับการชำระเงิน
@receiver(post_save, sender=Order)
def notify_seller_payment_received(sender, instance, **kwargs):
    if instance.payment_status == "paid":
        SellerNotification.objects.create(
            seller=instance.seller.user,
            message=f"💰 คำสั่งซื้อ #{instance.id} ได้รับการชำระเงินแล้ว"
        )

# ✅ แจ้งเตือนเมื่อมีคำขอคืนเงิน
@receiver(post_save, sender=RefundRequest)
def notify_seller_refund_request(sender, instance, created, **kwargs):
    if created:
        SellerNotification.objects.create(
            seller=instance.order.seller.user,
            message=f"⚠️ มีคำขอคืนเงินสำหรับคำสั่งซื้อ #{instance.order.id}"
        )

# ✅ แจ้งเตือนเมื่อมีรีวิวสินค้าใหม่
@receiver(post_save, sender=Review)
def notify_seller_new_review(sender, instance, created, **kwargs):
    if created:
        SellerNotification.objects.create(
            seller=instance.product.seller.user,
            message=f"⭐️ รีวิวใหม่สำหรับสินค้า {instance.product.name} โดย {instance.user.username}"
        )

from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import WithdrawalRequest, SellerNotification

@receiver(post_save, sender=WithdrawalRequest)
def notify_seller_withdrawal_request(sender, instance, created, **kwargs):
    # ตรวจสอบว่าไม่ใช่การสร้างคำขอใหม่ แต่เป็นการอัปเดต (อัปโหลดสลิป)
    if not created and instance.payment_proof:  
        SellerNotification.objects.create(
            seller=instance.seller.user,
            message=f"💵 คำขอถอนเงิน {instance.amount} บาท ได้รับการตรวจสอบแล้ว โปรดรอการดำเนินการ"
        )


# ✅ แจ้งเตือนเมื่อคำขอถอนเงินได้รับการอนุมัติ
@receiver(post_save, sender=WithdrawalRequest)
def notify_seller_withdrawal_approved(sender, instance, **kwargs):
    if instance.status == "approved":
        SellerNotification.objects.create(
            seller=instance.seller.user,
            message=f"✅ คำขอถอนเงิน {instance.amount} บาท ได้รับการอนุมัติแล้ว"
        )

# ✅ แจ้งเตือนเมื่อคำขอถอนเงินถูกปฏิเสธ
@receiver(post_save, sender=WithdrawalRequest)
def notify_seller_withdrawal_rejected(sender, instance, **kwargs):
    if instance.status == "rejected":
        SellerNotification.objects.create(
            seller=instance.seller.user,
            message=f"❌ คำขอถอนเงิน {instance.amount} บาท ถูกปฏิเสธ"
        )
