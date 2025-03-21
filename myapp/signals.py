
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



from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Post, Comment, Order, MemberNotification

# 📢 แจ้งเตือนเมื่อมีโพสต์ใหม่จากคนที่เราติดตาม
@receiver(post_save, sender=Post)
def notify_followers_new_post(sender, instance, created, **kwargs):
    if created:
        followers = instance.user.followers.all()  # ✅ เปลี่ยนจาก `author` เป็น `user`
        for follower in followers:
            MemberNotification.objects.create(
                user=follower.follower,  # ✅ ใช้ follower.follower เพื่อให้ได้ CustomUser instance
                message=f"📢 {instance.user.username} ได้โพสต์ใหม่: {instance.content[:50]}"
            )


# 💬 แจ้งเตือนเมื่อมีคอมเมนต์ในโพสต์ของเรา
@receiver(post_save, sender=Comment)
def notify_post_owner_new_comment(sender, instance, created, **kwargs):
    if created and instance.post.user != instance.user:  # ✅ เปลี่ยน `author` เป็น `user`
        MemberNotification.objects.create(
            user=instance.post.user,  # ✅ เปลี่ยนจาก `author` เป็น `user`
            message=f"💬 {instance.user.username} คอมเมนต์โพสต์ของคุณ: {instance.content[:50]}"
        )


# ❤️ แจ้งเตือนเมื่อมีคนกดไลค์โพสต์ของเรา
@receiver(post_save, sender=Post.likes.through)  # ใช้ ManyToMany signal
def notify_post_owner_new_like(sender, instance, **kwargs):
    post = instance.post
    liker = instance.user
    if post.author != liker:
        MemberNotification.objects.create(
            user=post.author,
            message=f"❤️ {liker.username} ถูกใจโพสต์ของคุณ!"
        )

# 📦 แจ้งเตือนสถานะคำสั่งซื้อ
@receiver(post_save, sender=Order)
def notify_buyer_order_status(sender, instance, **kwargs):
    MemberNotification.objects.create(
        user=instance.user,
        message=f"📦 คำสั่งซื้อของคุณ #{instance.id} ถูกเปลี่ยนเป็น {instance.status}"
    )
