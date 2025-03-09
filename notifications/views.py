from django.http import JsonResponse
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from .models import Notification
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import Notification
from myapp.models import Post, Follow, Cart, CartItem, Order, Review, Product

@login_required
def get_notifications(request):
    # 🔹 เอาฟิลเตอร์ is_read ออกก่อนชั่วคราว
    notifications = Notification.objects.filter(user=request.user).order_by('-created_at')

    print("🔔 จำนวนแจ้งเตือนที่พบ:", notifications.count())  # Debug log

    data = [{
        "sender": n.sender.username,
        "post_id": n.post.id if n.post else None,
        "type": n.notification_type
    } for n in notifications]

    return JsonResponse({"notifications": data})

@login_required
def notifications_list(request):
    notifications = Notification.objects.filter(user=request.user).order_by('-created_at')
    data = {'notifications': []}
    for n in notifications:
        # กำหนดข้อความตามประเภทแจ้งเตือน
        if n.notification_type == 'like':
            message = f"{n.sender.username} liked your post"
        elif n.notification_type == 'comment':
            message = f"{n.sender.username} commented on your post"
        else:
            message = "New notification"
        
        data['notifications'].append({
            'id': n.id,
            'sender': n.sender.username,
            'message': message,
            'post_id': n.post.id if n.post else None
        })
    return render(request, 'notification_list.html', {'notifications': notifications})

@login_required
def toggle_like(request, post_id):
    post = get_object_or_404(Post, id=post_id)
    user = request.user

    if post.likes.filter(id=user.id).exists():
        post.likes.remove(user)
        liked = False
    else:
        post.likes.add(user)
        liked = True

        # ✅ แจ้งเตือนเจ้าของโพสต์เมื่อมีคนกดไลค์
        create_notification(
            user=post.user,  # ✅ แจ้งเตือนเจ้าของโพสต์
            sender=user,  # ✅ ผู้ที่กดไลค์
            notification_type="like_post",
            post=post
        )

    return JsonResponse({"success": True, "liked": liked, "like_count": post.likes.count()})


from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from .models import Notification

@login_required
def get_notifications(request):
    """ ดึงแจ้งเตือนของผู้ใช้ """
    notifications = Notification.objects.filter(user=request.user, is_read=False).order_by('-created_at')
    
    data = [
        {
            "id": n.id,
            "sender": n.sender.username if n.sender else "System",
            "type": n.notification_type,
            "post_id": n.post.id if n.post else None,
            "order_id": n.order.id if n.order else None,
            "created_at": n.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        }
        for n in notifications
    ]
    
    return JsonResponse({"notifications": data})

@login_required
def mark_notification_as_read(request, notification_id):
    """ ทำเครื่องหมายแจ้งเตือนว่าอ่านแล้ว """
    notification = Notification.objects.filter(id=notification_id, user=request.user).first()
    if notification:
        notification.is_read = True
        notification.save()
        return JsonResponse({"success": True})
    return JsonResponse({"success": False, "error": "Notification not found"})

from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import Notification

@login_required
def all_notifications(request):
    """ ดึงการแจ้งเตือนจากทุกประเภทที่เกี่ยวข้องกับผู้ใช้ """
    notifications = Notification.objects.filter(user=request.user).order_by('-created_at')

    return render(request, "notifications.html", {"notifications": notifications})

from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import Notification

@login_required
def seller_notifications_list(request):
    """ ดึงแจ้งเตือนทั้งหมดของผู้ขาย """
    notifications = Notification.objects.filter(
        user=request.user,
        notification_type__in=[
            'new_order', 'new_review', 'refund_request',
            'refund_completed', 'order_shipped', 'refund_approved', 'refund_rejected'
        ]
    ).order_by('-created_at')

    print(f"📢 แจ้งเตือนทั้งหมดของ {request.user.username}: {notifications.count()} รายการ")  # ✅ Debugging

    return render(request, 'notificationsellers.html', {'notifications': notifications})



