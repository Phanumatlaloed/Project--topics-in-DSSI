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



"""def create_notification(user, sender, notification_type, post=None):
    #ฟังก์ชันสร้างแจ้งเตือนใหม่ 
    Notification.objects.create(
        user=user,
        sender=sender,
        notification_type=notification_type,
        post=post
    )


@login_required
def create_post(request):
    if request.method == "POST":
        content = request.POST.get('content', '').strip()
        if not content:
            return JsonResponse({'success': False, 'message': 'โพสต์ต้องมีเนื้อหา'}, status=400)

        post = Post.objects.create(user=request.user, content=content)

        # ✅ แจ้งเตือนให้ followers ของผู้ใช้
        followers = Follow.objects.filter(following=request.user)
        for follower in followers:
            create_notification(user=follower.follower, sender=request.user, notification_type='new_post', post=post)

        return JsonResponse({'success': True, 'post_id': post.id}, status=201)

    return JsonResponse({'success': False, 'message': 'Invalid request'}, status=400)

@login_required
def add_comment(request, post_id):
    post = get_object_or_404(Post, id=post_id)

    if request.method == "POST":
        content = request.POST.get('content')
        if content:
            comment = Comment.objects.create(post=post, user=request.user, content=content)

            # ✅ แจ้งเตือนเจ้าของโพสต์
            create_notification(user=post.user, sender=request.user, notification_type='new_comment', post=post)

            return JsonResponse({
                'success': True,
                'username': request.user.username,
                'content': comment.content
            }, status=201)

    return JsonResponse({'success': False, 'message': 'Invalid request'}, status=400)

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

        # ✅ แจ้งเตือนเจ้าของโพสต์
        create_notification(user=post.user, sender=user, notification_type='like_post', post=post)

    return JsonResponse({"success": True, "liked": liked, "like_count": post.likes.count()})

@login_required
def share_post(request, post_id):
    if request.method == "POST":
        original_post = get_object_or_404(Post, id=post_id)
        shared_post = Post.objects.create(
            user=request.user,
            content=f"📢 Shared from {original_post.user.username}:\n{original_post.content}",
            shared_from=original_post
        )

        # ✅ แจ้งเตือนเจ้าของโพสต์ต้นฉบับ
        create_notification(user=original_post.user, sender=request.user, notification_type='share_post', post=original_post)

        return JsonResponse({'success': True, 'message': "โพสต์ถูกแชร์แล้ว!", 'post_id': shared_post.id}, status=201)

    return JsonResponse({'success': False, 'message': 'Invalid request'}, status=400)

@login_required
def follow_user(request, user_id):
    user_to_follow = get_object_or_404(CustomUser, id=user_id)

    if user_to_follow == request.user:
        return JsonResponse({"success": False, "message": "You cannot follow yourself."}, status=400)

    follow, created = Follow.objects.get_or_create(follower=request.user, following=user_to_follow)

    if created:
        # ✅ แจ้งเตือนผู้ถูกติดตาม
        create_notification(user=user_to_follow, sender=request.user, notification_type='new_follower')

    return JsonResponse({"success": True, "message": "Followed successfully."})

@login_required
def confirm_order(request):
    cart = Cart.objects.get(user=request.user)
    cart_items = CartItem.objects.filter(cart=cart)

    if not cart_items:
        messages.error(request, "ไม่มีสินค้าในตะกร้า กรุณาเลือกสินค้าก่อนสั่งซื้อ!")
        return redirect('cart')

    orders_by_seller = {}
    for item in cart_items:
        seller = item.product.seller
        if seller not in orders_by_seller:
            orders_by_seller[seller] = []
        orders_by_seller[seller].append(item)

    for seller, items in orders_by_seller.items():
        order = Order.objects.create(user=request.user, seller=seller, status="pending")

        # ✅ แจ้งเตือนเจ้าของร้านค้า
        create_notification(user=seller.user, sender=request.user, notification_type='new_order')

    cart_items.delete()  # ✅ ล้างตะกร้าหลังจากสร้างคำสั่งซื้อ
    return redirect('order_history')

@login_required
def add_review(request, product_id):
    product = get_object_or_404(Product, id=product_id)

    if request.method == "POST":
        rating = request.POST.get("rating")
        comment = request.POST.get("comment")
        Review.objects.create(user=request.user, product=product, rating=rating, comment=comment)

        # ✅ แจ้งเตือนเจ้าของสินค้า
        create_notification(user=product.seller.user, sender=request.user, notification_type='new_review')

        return redirect('product_detail', product_id=product.id)

@login_required
def get_notifications(request):
    notifications = Notification.objects.filter(user=request.user).order_by('-created_at')

    data = [{
        "sender": n.sender.username if n.sender else "System",
        "post_id": n.post.id if n.post else None,
        "type": n.notification_type,
        "created_at": n.created_at.strftime('%Y-%m-%d %H:%M')
    } for n in notifications]

    return JsonResponse({"notifications": data})
"""