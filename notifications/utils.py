from .models import Notification

def create_notification(user, sender, notification_type, post=None, group_post=None, order=None):
    if post and group_post:
        raise ValueError("Cannot assign both post and group_post to a notification.")

    notification = Notification.objects.create(
        user=user,
        sender=sender,
        notification_type=notification_type,
        post=post,
        group_post=group_post,  # ✅ เพิ่มการรองรับ group_post
        order=order
    )
    return notification

def create_seller_notification(user, sender, notification_type, order=None):
    """ ฟังก์ชันสร้างแจ้งเตือนสำหรับผู้ขาย """
    if notification_type not in ['new_order', 'new_review', 'refund_request', 'refund_completed', 'order_shipped', 'refund_approved', 'refund_rejected']:
        raise ValueError("Invalid notification type for seller.")

    Notification.objects.create(
        user=user,  # ✅ ผู้ขาย
        sender=sender,  # ✅ ลูกค้าหรือระบบ
        notification_type=notification_type,
        order=order
    )


