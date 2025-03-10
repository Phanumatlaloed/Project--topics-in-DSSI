from django.db import models
from django.contrib.auth import get_user_model
from myapp.models import Post, GroupPost, Order, GroupPost, Product

User = get_user_model()

class Notification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="notifications")
    sender = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name="sent_notifications")
    notification_type = models.CharField(max_length=20, choices=[
        ('new_post', 'New Post'),
        ('new_comment', 'New Comment'),
        ('like_post', 'Post Liked'),
        ('share_post', 'Post Shared'),
        ('new_follower', 'New Follower'),
        ('refund_request', 'Refund Request'),
        ('like_group_post', 'Group Post Liked'),  # ✅ เพิ่มประเภทการแจ้งเตือน
        ('comment_group_post', 'Group Post Commented'),  # ✅ เพิ่มประเภทการแจ้งเตือน
        ('new_order', 'New Order'),
        ('new_review', 'New Review'),
        ('refund_request', 'Refund Request'),
        ('refund_completed', 'Refund Completed'),
        ('order_shipped', 'Order Shipped'),
        ('refund_approved', 'Refund Approved'),
        ('refund_rejected', 'Refund Rejected'),
    ])
    
    post = models.ForeignKey(Post, on_delete=models.SET_NULL, null=True, blank=True)
    group_post = models.ForeignKey(GroupPost, on_delete=models.CASCADE, null=True, blank=True, related_name='notifications')  # ✅ เพิ่ม GroupPost
    order = models.ForeignKey(Order, on_delete=models.SET_NULL, null=True, blank=True)
    product = models.ForeignKey(Product, on_delete=models.SET_NULL, null=True, blank=True)  # ✅ สินค้าที่ถูกรีวิว

    created_at = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user.username} - {self.notification_type}"



class Post(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.TextField()

class GroupPost(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="group_posts")  # ✅ เปลี่ยน related_name
    content = models.TextField()
    group = models.ForeignKey(GroupPost, on_delete=models.CASCADE)  # ✅ ระบุ myapp


    
