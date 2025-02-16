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
