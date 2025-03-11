from .models import Notification


def create_seller_notification(user, sender, notification_type, order=None):
    """ ฟังก์ชันสร้างแจ้งเตือนสำหรับผู้ขาย """
    if notification_type not in ['new_order', 'new_review', 'refund_request', 'refund_completed', 'order_shipped', 'refund_approved', 'refund_rejected']:
        raise ValueError("❌ Invalid notification type for seller.")

    print(f"🔔 กำลังบันทึกแจ้งเตือน '{notification_type}' ให้กับ {user.username}")  # ✅ Debugging

    Notification.objects.create(
        user=user,  # ✅ ผู้ขาย
        sender=sender,  # ✅ ลูกค้าหรือระบบ
        notification_type=notification_type,
        order=order
    )

from .models import Notification

def create_notification(user, sender, message, notification_type, post=None, order=None):
    Notification.objects.create(
        user=user,
        sender=sender,
        message=message,
        notification_type=notification_type,
        post=post,
        order=order
    )
