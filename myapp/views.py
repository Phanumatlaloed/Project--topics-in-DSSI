from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt  # ✅ เพิ่มการ import
from django.contrib.auth import get_user_model, update_session_auth_hash
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.utils import timezone
import os
from decimal import Decimal
from django.db.models import Q
from django.middleware.csrf import get_token
from requests import post
from myapp.models import *
from .models import *
from myapp.forms import *
from django.contrib.auth.decorators import user_passes_test
import json
from django.db.models import Sum, F, DecimalField, ExpressionWrapper, Q
from datetime import datetime
from django.core.exceptions import PermissionDenied



User = get_user_model()  # ✅ ใช้ CustomUser แทน auth.User

from django.shortcuts import render, redirect, get_object_or_404
from .models import Product, Review, ReviewMedia
from django.contrib.auth.decorators import login_required
User = get_user_model()  # ✅ ใช้ CustomUser แทน auth.User
from django.contrib.auth import get_user_model
User = get_user_model()  # ✅ ใช้ CustomUser แทน



class CustomUserCreationForm(UserCreationForm):
    """ ใช้ CustomUser ในฟอร์ม """
    class Meta:
        model = User  # ✅ ใช้ CustomUser แทน User ปกติ
        fields = ['username','email', 'password1', 'password2']

#สมัครใช้งาน
from django.db import IntegrityError
def register(request):
    if request.method == "POST":
        first_name = request.POST.get("first_name")
        last_name = request.POST.get("last_name")
        email = request.POST.get("email")
        username = request.POST.get("username")
        password = request.POST.get("password")
        gender = request.POST.get("gender")
        date_of_birth = request.POST.get("date_of_birth")

        # ตรวจสอบข้อมูลที่กรอก
        if not all([first_name, last_name, email, username, password, gender, date_of_birth]):
            messages.error(request, "กรุณากรอกข้อมูลให้ครบทุกช่อง")
            return render(request, "register.html")

        # ตรวจสอบว่าอีเมลนี้ถูกใช้งานใน Role เดียวกันหรือไม่
        if CustomUser.objects.filter(email=email, role='member').exists():
            messages.error(request, "อีเมลนี้ถูกใช้งานแล้วในบัญชีสมาชิก")
            return render(request, "register.html")

        # ตรวจสอบว่าชื่อผู้ใช้ถูกใช้งานแล้วหรือไม่
        if CustomUser.objects.filter(username=username).exists():
            messages.error(request, "ชื่อผู้ใช้นี้ถูกใช้งานแล้ว")
            return render(request, "register.html")

        try:
            # ✅ สร้าง User
            user = CustomUser.objects.create_user(
                username=username,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                role='member'
            )

            # ✅ ตรวจสอบว่าผู้ใช้มี Member อยู่แล้วหรือไม่
            if not Member.objects.filter(user=user).exists():
                Member.objects.create(user=user, gender=gender, date_of_birth=date_of_birth)

            messages.success(request, "สมัครสมาชิกสำเร็จ! กรุณาเข้าสู่ระบบ")
            return redirect("login")

        except IntegrityError as e:
            messages.error(request, f"❌ การสมัครล้มเหลว: {str(e)}")
            return render(request, "register.html")

    return render(request, "register.html")

from django.db.models import Q

def all_posts(request):
    query = request.GET.get('query', '')  # รับค่าค้นหา
    if query:
        posts = Post.objects.filter(
            Q(content__icontains=query) |  # ✅ ค้นหาคำในเนื้อหาโพสต์
            Q(user__username__icontains=query)  # ✅ ค้นหาจากชื่อผู้ใช้
        ).order_by('-created_at')
    else:
        posts = Post.objects.all().order_by('-created_at')  # แสดงโพสต์ทั้งหมด

    products = Product.objects.all()[:6]  # ✅ ดึงสินค้าสูงสุด 6 รายการ

    return render(request, "all_posts.html", {"posts": posts, "products": products, "query": query})


def search_content(request):
    query = request.GET.get('query', '')
    posts = Post.objects.filter(title__icontains=query) if query else Post.objects.all()

    return render(request, 'search_content.html', {'query': query, 'posts': posts})

#login
# ✅ ฟังก์ชันล็อกอิน
def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            if user.role == 'member':  # ✅ ตรวจสอบเฉพาะ role 'member'
                login(request, user)
                return redirect('home')
            else:
                messages.error(request, '❌ เฉพาะสมาชิก (Member) เท่านั้นที่สามารถเข้าสู่ระบบได้!')
        else:
            messages.error(request, '❌ ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง')

    return render(request, 'login.html')

import random
from django.core.mail import send_mail
from django.contrib.auth import get_user_model
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.hashers import make_password

User = get_user_model()

# ✅ ฟังก์ชันส่ง OTP ไปยังอีเมล
def send_otp_email(request, email):
    otp = random.randint(100000, 999999)  # ✅ สร้าง OTP 6 หลัก
    request.session['otp'] = otp  # ✅ เก็บ OTP ใน session
    request.session['reset_email'] = email  # ✅ เก็บอีเมลของผู้ใช้

    subject = "Your OTP for Password Reset"
    message = f"Your OTP code is: {otp}"
    send_mail(subject, message, 'noreply@yourdomain.com', [email])

    print(f"✅ OTP ส่งไปที่ {email}: {otp}")  # ✅ Debug OTP ใน Terminal

# ✅ ฟังก์ชันขอรีเซ็ตรหัสผ่าน (รับอีเมล)
def forgot_password(request):
    if request.method == "POST":
        email = request.POST.get('email')

        if not User.objects.filter(email=email).exists():
            messages.error(request, "This email is not registered.")
            return redirect('password_reset')

        send_otp_email(request, email)  # ✅ ส่ง OTP ไปยังอีเมล
        messages.success(request, "OTP has been sent to your email.")
        return redirect('reset_password')  # ✅ นำไปที่หน้ากรอก OTP

    return render(request, "password_reset.html")

# ✅ ฟังก์ชันรีเซ็ตรหัสผ่าน (ตรวจสอบ OTP และเปลี่ยนรหัสผ่าน)
def reset_password(request):
    if request.method == "POST":
        otp_input = request.POST.get("otp")
        new_password = request.POST.get("new_password")

        session_otp = request.session.get("otp")
        email = request.session.get("reset_email")

        if not session_otp or not email:
            messages.error(request, "Session expired. Please request OTP again.")
            return redirect("password_reset")

        if str(session_otp) != str(otp_input):
            messages.error(request, "Invalid OTP. Please try again.")
            return redirect("reset_password")

        user = User.objects.get(email=email)
        user.password = make_password(new_password)  # ✅ เปลี่ยนรหัสผ่าน
        user.save()

        del request.session["otp"]  # ✅ ลบ OTP ออกจาก session
        del request.session["reset_email"]

        messages.success(request, "Password changed successfully! You can now log in.")
        return redirect("login")

    return render(request, "reset_password.html")

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Q
from .models import Post, Product, Follow, BlockedUser  # ✅ นำเข้าโมเดลที่เกี่ยวข้อง
from notifications.models import Notification  # ✅ นำเข้าโมเดล Notification

@login_required
def home(request):
    """ 
    แสดงหน้า Home โดยกรองโพสต์ที่ถูกบล็อก, ถูกรีพอร์ต ยกเว้นโพสต์ของตัวเอง และแสดงสินค้าด้วย
    """   
    if request.user.role != 'member':
        messages.error(request, "❌ เฉพาะสมาชิก (Member) เท่านั้นที่สามารถเข้าถึงหน้านี้!")
        return redirect('login')

    # ✅ ดึงรายการผู้ใช้ที่ถูกบล็อกก่อน
    blocked_users = list(BlockedUser.objects.filter(blocked_by=request.user).values_list('blocked_user', flat=True))

    # ✅ ดึงโพสต์ให้แสดงเฉพาะ:
    # - โพสต์ที่ **ไม่ถูกรีพอร์ต**
    # - โพสต์ของตัวเองต้องแสดงเสมอ
    # - โพสต์ของผู้ใช้ที่ถูกบล็อกต้องถูกซ่อน
    posts = Post.objects.filter(
        Q(is_reported=False) | Q(user=request.user)  # ✅ โพสต์ของตัวเองต้องแสดง
    ).exclude(
        Q(user__id__in=blocked_users) & ~Q(user=request.user)  # ✅ ซ่อนโพสต์ของผู้ใช้ที่ถูกบล็อก แต่แสดงโพสต์ของตัวเอง
    ).order_by('-created_at')

    # ✅ ดึงรายชื่อผู้ใช้ที่ผู้ใช้ปัจจุบันติดตามอยู่
    following_users = list(Follow.objects.filter(follower=request.user).values_list('following_id', flat=True))

    # ✅ เก็บ `followed_users` เป็นเซ็ตเพื่อใช้ใน template
    followed_users = set(following_users)

    # ✅ ดึงสินค้าที่แนะนำมาแสดง (เช่น 6 รายการล่าสุด)
    products = Product.objects.all()[:6]  

    # ✅ ดึงการแจ้งเตือนของผู้ใช้
    notifications = Notification.objects.filter(user=request.user).order_by('-created_at')[:10]


    return render(request, 'home.html', {
        'username': request.user.username,
        'posts': posts,
        'following_users': list(following_users),  # ✅ ส่งค่าผู้ใช้ที่ติดตามไปยังเทมเพลต
        'following_users': following_users,
        'followed_users': followed_users,
        'products': products,  # ✅ ส่งสินค้าพร้อมโพสต์ไปยังเทมเพลต
        'notifications': notifications,  # ✅ ส่งการแจ้งเตือนไปยังเทมเพลต
    })

#logout
# ✅ ฟังก์ชันล็อกเอาต์
def logout_view(request):
    logout(request)
    messages.success(request, "คุณได้ออกจากระบบเรียบร้อยแล้ว")
    return redirect('login')


#forgotpass
def forgotPass(request):
    return render(request, 'forgotPass.html')

#community
def community(request):
    return render(request, 'community.html')

from django.shortcuts import render, redirect
from django.contrib import messages
from .models import Post, PostMedia

def profile(request):

    products = Product.objects.all()[:6]  

    user = request.user  # ดึงข้อมูลของผู้ใช้ที่ล็อกอินอยู่
    profile = get_object_or_404(Member, user=user)  # ดึงโปรไฟล์ของผู้ใช้
    posts = Post.objects.filter(user=user, is_reported=False).order_by('-created_at')  # กรองโพสต์ที่ไม่ถูกรีพอร์ต


    if request.method == 'POST':
        profile = user.profile

        # Update user information
        user.first_name = request.POST.get('first_name', user.first_name)
        user.last_name = request.POST.get('last_name', user.last_name)
        user.email = request.POST.get('email', user.email)

        # Update profile information
        profile.title = request.POST.get('title', profile.title)
        profile.about = request.POST.get('about', profile.about)

        # Save changes
        user.save()
        profile.save()

        messages.success(request, 'Profile updated successfully!')
        return redirect('profile')

    return render(request, 'profile.html', {
        'user': user,
        'posts': posts,
        'products': products,  # ส่งสินค้าพร้อมโพสต์ไปยังเทมเพลต
        })


def profile_edit(request):
    user = request.user
    member = user.member_profile  # เชื่อมโยงผ่าน related_name ใน Member model

    if request.method == "POST":
        user_form = UserEditForm(request.POST, instance=user)
        member_form = MemberEditForm(request.POST, instance=member)

        if user_form.is_valid() and member_form.is_valid():
            user_form.save()
            member_form.save()
            messages.success(request, "ข้อมูลโปรไฟล์ของคุณถูกแก้ไขเรียบร้อยแล้ว")
            return redirect('profile_edit')  # เปลี่ยนเส้นทางไปยังหน้าโปรไฟล์หลังแก้ไขเสร็จ
        else:
            messages.error(request, "กรุณาตรวจสอบข้อมูลอีกครั้ง")
    else:
        user_form = UserEditForm(instance=user)
        member_form = MemberEditForm(instance=member)

    return render(request, 'profile_edit.html', {
        'user_form': user_form,
        'member_form': member_form,
    })


#โพสในหน้าหลัก
@login_required
def create_post(request):
    if request.method == "POST":
        content = request.POST.get('content', '').strip()
        is_community = request.POST.get('is_community', 'false') == 'true'
        image_files = request.FILES.getlist('images')
        video_files = request.FILES.getlist('videos')
        #group_id = request.POST.get('group_id')  # ✅ ดึงค่า group_id

        if not content and not image_files and not video_files:
            return JsonResponse({'success': False, 'message': 'โพสต์ต้องมีข้อความ หรือไฟล์สื่อ'}, status=400)

        post = Post.objects.create(user=request.user, content=content, is_community_post=is_community)

        for img in image_files:
            PostMedia.objects.create(post=post, file=img, media_type='image')

        for vid in video_files:
            PostMedia.objects.create(post=post, file=vid, media_type='video')

        return JsonResponse({
            'success': True, 
            'post_id': post.id, 
            'username': request.user.username,
            'content': content
        }, status=201)

    return JsonResponse({'success': False, 'message': 'Invalid request'}, status=400)

#ลบโพสต์ในหน้าหลัก
@login_required
def delete_post(request, post_id):
    """ ฟังก์ชันลบโพสต์และไฟล์แนบที่เกี่ยวข้อง """
    if request.method == "POST":
        post = Post.objects.filter(id=post_id).first()  # ✅ ใช้ `.filter().first()` เพื่อลด error

        if not post:
            return JsonResponse({"success": False, "message": "โพสต์นี้ถูกลบไปแล้วหรือไม่มีอยู่จริง"}, status=404)

        # ✅ ตรวจสอบว่าเป็นเจ้าของโพสต์
        if post.user != request.user:
            return JsonResponse({"success": False, "message": "คุณไม่มีสิทธิ์ลบโพสต์นี้"}, status=403)

        # ✅ เช็คว่าโพสต์นี้เป็นโพสต์ที่ถูกแชร์มาหรือไม่
        if post.shared_from:
            # ✅ ถ้าเป็นโพสต์ที่แชร์มา แค่ลบโพสต์นี้ ไม่ต้องลบโพสต์ต้นฉบับ
            post.delete()
            return JsonResponse({"success": True, "message": "โพสต์แชร์ถูกลบเรียบร้อยแล้ว แต่โพสต์ต้นฉบับยังคงอยู่"}, status=200)

        # ✅ ลบไฟล์แนบถ้าเป็นโพสต์ต้นฉบับ
        for media in post.media.all():
            if media.file:
                file_path = os.path.join(settings.MEDIA_ROOT, str(media.file))
                if os.path.exists(file_path):
                    os.remove(file_path)
            media.delete()

        post.delete()  # ✅ ลบโพสต์ต้นฉบับ
        return JsonResponse({"success": True, "message": "โพสต์ต้นฉบับถูกลบเรียบร้อยแล้ว!"}, status=200)
    
    return JsonResponse({"success": False, "message": "Invalid request method"}, status=400)


@login_required
def edit_post(request, post_id):
    """ ฟังก์ชันแก้ไขโพสต์ """
    post = get_object_or_404(Post, id=post_id)

    # ✅ ตรวจสอบว่าเป็นเจ้าของโพสต์หรือไม่
    if post.user != request.user:
        return JsonResponse({"success": False, "message": "คุณไม่มีสิทธิ์แก้ไขโพสต์นี้"}, status=403)

    if request.method == "POST":
        form = EditPostForm(request.POST, instance=post)

        if form.is_valid():
            form.save()

            # ✅ ดึงไฟล์รูปภาพและวิดีโอที่อัปโหลดใหม่
            images = request.FILES.getlist("images")
            videos = request.FILES.getlist("videos")

            for file in images:
                PostMedia.objects.create(post=post, file=file, media_type='image')

            for file in videos:
                PostMedia.objects.create(post=post, file=file, media_type='video')

            # ✅ กลับไปหน้าหลักทันทีหลังจากบันทึก
            return redirect('home')

    else:
        form = EditPostForm(instance=post)

    return render(request, "edit_post.html", {"post": post, "form": form})


from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from .models import PostMedia
import os
@login_required
@login_required
def delete_media(request, media_id):
    print(f"📌 DELETE request received for media_id: {media_id}")  # ✅ Debug Log

    if request.method == "DELETE":
        # ✅ ลองค้นหาในทั้งสองโมเดล
        media = (
            PostMedia.objects.filter(id=media_id).first() or
            GroupPostMedia.objects.filter(id=media_id).first()
        )

        if not media:
            return JsonResponse({"success": False, "error": "Media not found"}, status=404)

        # ✅ ตรวจสอบไฟล์ที่เซิร์ฟเวอร์
        if media.file:
            file_path = media.file.path
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)  # ✅ ลบไฟล์จากเซิร์ฟเวอร์
                    media.delete()  # ✅ ลบจากฐานข้อมูล
                    return JsonResponse({"success": True})
                except Exception as e:
                    return JsonResponse({"success": False, "error": str(e)}, status=500)
            else:
                media.delete()  # ✅ ลบจากฐานข้อมูลแม้ว่าไฟล์ไม่มีอยู่แล้ว
                return JsonResponse({"success": True, "message": "File not found but deleted from database"})

        return JsonResponse({"success": False, "error": "File does not exist"}, status=404)

    return JsonResponse({"success": False, "error": "Invalid request method"}, status=400)




from django.contrib.auth import get_user_model

User = get_user_model()  # ✅ ใช้ CustomUser แทน auth.User

from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from .models import Post  # ✅ ตรวจสอบว่า import ถูกต้อง

# @login_required
# def toggle_like(request, post_id):
#     if request.method == "POST":
#         post = get_object_or_404(Post, id=post_id)
#         user = request.user  # ✅ ใช้ request.user ตรงๆ
        
#         if post.likes.filter(id=user.id).exists():
#             post.likes.remove(user)  # ✅ ถ้าเคยไลค์ -> กดอีกครั้งเพื่อลบ
#             liked = False
#         else:
#             post.likes.add(user)  # ✅ ถ้ายังไม่เคยไลค์ -> กดไลค์
#             liked = True

#         like_count = post.likes.count()

#         if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
#             return JsonResponse({"success": True, "liked": liked, "like_count": like_count})

#         return redirect(request.META.get('HTTP_REFERER', 'home'))

#     return JsonResponse({"success": False, "error": "Invalid request method"}, status=400)

@login_required
def toggle_like(request, post_id):
    if request.method == "POST":
        post = get_object_or_404(Post, id=post_id)
        user = request.user
        
        if post.likes.filter(id=user.id).exists():
            # ถ้าเคยไลค์แล้ว -> กดอีกครั้งเพื่อยกเลิกการไลค์
            post.likes.remove(user)
            liked = False
        else:
            # ถ้ายังไม่เคยไลค์ -> กดไลค์
            post.likes.add(user)
            liked = True
            
            # สร้างการแจ้งเตือนโดยตรงเมื่อมีคนกดไลค์
            # ไม่ต้องแจ้งเตือนถ้าเป็นโพสต์ของตัวเอง
            if post.user != user:
                MemberNotification.objects.create(
                    user=post.user,
                    message=f"❤️ {user.username} ถูกใจโพสต์ของคุณ!",
                    is_read=False  # ตั้งค่าเริ่มต้นเป็นยังไม่ได้อ่าน
                )
                print(f"DEBUG: สร้างการแจ้งเตือนกดไลค์แล้ว -> ผู้รับ: {post.user.username}, ผู้ส่ง: {user.username}")

        like_count = post.likes.count()

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({"success": True, "liked": liked, "like_count": like_count})

        return redirect(request.META.get('HTTP_REFERER', 'home'))

    return JsonResponse({"success": False, "error": "Invalid request method"}, status=400)


@login_required
def post_detail(request, post_id):
    """ แสดงรายละเอียดโพสต์ พร้อมสินค้าแนะนำ """
    post = get_object_or_404(Post, id=post_id)
    products = Product.objects.all()[:6]  # ✅ ดึงสินค้า 6 รายการแรกมาแสดง

    following_users = list(Follow.objects.filter(follower=request.user).values_list('following_id', flat=True))

    # ✅ เก็บ `followed_users` เป็นเซ็ตเพื่อใช้ใน template
    followed_users = set(following_users)

    return render(request, 'post_detail.html', {
        'post': post,
        'products': products,  # ✅ ส่ง products ไปที่ template
        'following_users': list(following_users),  # ✅ ส่งค่าผู้ใช้ที่ติดตามไปยังเทมเพลต
        'following_users': following_users,
        'followed_users': followed_users,
    })

@login_required
def post_like_detail(request, post_id):
    """ แสดงรายละเอียดโพสต์ """
    post = get_object_or_404(Post, id=post_id)
    return render(request, 'post_like_detail.html', {'post': post})

#หน้าบันทึก
@login_required
def savelist(request):
    """ แสดงโพสต์ที่ถูกบันทึกโดยผู้ใช้ (เฉพาะ Member เท่านั้น) """
    try:
        member = request.user.member_profile  # ✅ ดึง `Member` จาก `CustomUser`
        member = Member.objects.get(user=request.user)
    except Member.DoesNotExist:
        messages.error(request, "บัญชีของคุณยังไม่มีโปรไฟล์สมาชิก")
        return redirect("profile")

    if request.user.role != 'member':
        messages.error(request, "❌ เฉพาะสมาชิก (Member) เท่านั้นที่สามารถเข้าถึงหน้านี้!")
        return redirect('login')

    saved_posts = SavedPost.objects.filter(user=request.user)  # ✅ ใช้ `CustomUser`
    saved_group_posts = SavedGroupPost.objects.filter(user=member)  # ✅ ใช้ `Member` จาก `member_profile`

    return render(request, "savelist.html", {
        "saved_posts": saved_posts,  
        "saved_group_posts": saved_group_posts,  
    })


#บันทึกโพสต์หน้าหลัก
from django.db import transaction

@login_required
def saved_post(request, post_id):
    """ บันทึก/ลบโพสต์จาก Saved List """
    post = get_object_or_404(Post, id=post_id)
    user = request.user  # ✅ ใช้ `CustomUser`

    with transaction.atomic():  # ✅ ใช้ transaction ป้องกัน error
        saved_post, created = SavedPost.objects.get_or_create(user=user, post=post)

        if not created:
            saved_post.delete()
            is_saved = False
        else:
            is_saved = True

    # ✅ ตรวจสอบสถานะว่าข้อมูลยังอยู่จริงไหม
    is_saved = SavedPost.objects.filter(user=user, post=post).exists()

    # ✅ ตรวจสอบ AJAX Request
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({
            "success": True,
            "saved": is_saved,  # ✅ ค่าความจริงจาก DB
        })

    return redirect(request.META.get('HTTP_REFERER', '/'))

#บันทึกโพสต์หน้าหลัก
@login_required
def remove_saved_post(request, post_id):
    """ ฟังก์ชันลบโพสต์ออกจาก Saved List """
    post = get_object_or_404(Post, id=post_id)
    user = request.user  # ✅ ใช้ CustomUser โดยตรง ไม่ต้องใช้ member_profile

    try:
        saved_post = SavedPost.objects.get(user=user, post=post)
        saved_post.delete()
        return JsonResponse({'success': True, 'message': 'Post removed from saved list'}, status=200)
    except SavedPost.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Post not found in saved list'}, status=404)
    
# @login_required
# def add_comment(request, post_id):
#     post = get_object_or_404(Post, id=post_id)

#     if request.method == "POST":
#         content = request.POST.get('content')
#         if content:
#             comment = Comment.objects.create(post=post, user=request.user, content=content)
#             return JsonResponse({
#                 'success': True,
#                 'message': 'Comment added successfully!',
#                 'username': request.user.username,  # ✅ ส่งชื่อผู้ใช้กลับไป
#                 'content': comment.content,
#                 "is_owner": True,  # ส่งค่ากลับไปว่าเป็นเจ้าของคอมเมนต์
#             }, status=201)

#         return JsonResponse({'success': False, 'message': 'Comment cannot be empty!'}, status=400)

#     return JsonResponse({'success': False, 'message': 'Invalid request!'}, status=400)

from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from .models import Comment, Post
#เพิ่มคอมเม้นในหน้าแรก
@login_required
def add_comment(request, post_id):
    if request.method == "POST":
        content = request.POST.get("content", "").strip()
        if not content:
            return JsonResponse({"success": False, "message": "เนื้อหาว่างเปล่า"})

        post = Post.objects.get(id=post_id)
        comment = Comment.objects.create(user=request.user, post=post, content=content)

        return JsonResponse({
            "success": True,
            "comment_id": comment.id,
            "content": comment.content,
            "username": request.user.username,
            "user_avatar": request.user.member_profile.profile_picture.url if request.user.member_profile.profile_picture else "/static/images/default-profile.png",
            "created_at": "เมื่อสักครู่"
        })


#หน้าชุมชน
@login_required
def community_list(request):
    """ แสดงรายการกลุ่ม Community สำหรับเฉพาะผู้ใช้ที่เป็น Member """
    if request.user.role != 'member':
        messages.error(request, "❌ เฉพาะสมาชิก (Member) เท่านั้นที่สามารถเข้าถึงหน้านี้!")
        return redirect('login')

    groups = CommunityGroup.objects.all()
    return render(request, 'community_list.html', {'groups': groups})

#หน้าสร้างกลุ่มในชุมชน
@login_required
def create_group(request):
    if request.method == 'POST':
        form = CommunityGroupForm(request.POST, request.FILES)
        if form.is_valid():
            # ✅ เช็คว่าผู้ใช้ได้อัปโหลดรูปหรือไม่
            if not request.FILES.get('image'):
                messages.error(request, "⚠️ กรุณาอัปโหลดรูปภาพกลุ่มก่อนสร้าง!")
                return render(request, 'create_group.html', {'form': form})

            group = form.save(commit=False)
            group.created_by = request.user
            group.save()
            group.members.add(request.user)  # ✅ ให้ผู้สร้างเป็นสมาชิกกลุ่มอัตโนมัติ
            messages.success(request, "✅ Group created successfully!")
            return redirect('community_list')
        else:
            messages.error(request, "⚠️ กรุณากรอกข้อมูลให้ครบทุกช่องก่อนสร้างกลุ่ม!")  # ✅ แจ้งเตือนถ้าข้อมูลไม่ครบ
    else:
        form = CommunityGroupForm()

    return render(request, 'create_group.html', {'form': form})

#แก้ไขรายละเอียดกลุ่มที่สร้างในชุมชน
@login_required
def edit_group(request, group_id):
    """ ให้เจ้าของกลุ่มสามารถแก้ไขรายละเอียดกลุ่ม """
    group = get_object_or_404(CommunityGroup, id=group_id, created_by=request.user)

    if request.method == "POST":
        form = CommunityGroupForm(request.POST, request.FILES, instance=group)
        if form.is_valid():
            form.save()
            messages.success(request, "ข้อมูลกลุ่มอัปเดตเรียบร้อย!")
            return redirect('group_detail', group_id=group.id)
    else:
        form = CommunityGroupForm(instance=group)

    return render(request, 'edit_group.html', {'form': form, 'group': group})

#ลบกลุ่มที่สร้างในหน้าชุมชน
@login_required
def delete_group(request, group_id, post_id):
    """ ให้เจ้าของกลุ่มสามารถลบกลุ่ม """
    post = get_object_or_404(GroupPost, id=post_id, group=group, user=request.user)

    group = get_object_or_404(CommunityGroup, id=group_id, created_by=request.user)
    if request.method == "POST":
        post.delete()
        return JsonResponse({"success": True, "message": "โพสต์ถูกลบแล้ว!"})

    return JsonResponse({"success": False, "message": "Invalid request"}, status=400)

#รายละเอียดในกลุ่ม
from django.http import JsonResponse
@login_required
def group_detail(request, group_id):
    group = get_object_or_404(CommunityGroup, id=group_id)
    
    is_member = request.user in group.members.all()
    # ✅ ป้องกันไม่ให้เห็นโพสต์ ถ้าไม่ได้เป็นสมาชิก
    # ✅ ดึงสินค้าที่แนะนำมาแสดง (เช่น 6 รายการล่าสุด)
    products = Product.objects.all()[:6]

    posts = GroupPost.objects.filter(group=group).order_by('-created_at') if is_member else None

    if request.method == "POST":
        content = request.POST.get('content', '').strip()
        image = request.FILES.get('image')
        video = request.FILES.get('video')

        if content or image or video:
            post = GroupPost.objects.create(
                group=group,
                user=request.user,  
                content=content,
                image=image,
                video=video
            )

            # ✅ ถ้า request เป็น AJAX ให้ส่ง JSON Response กลับไป
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                    'success': True,
                    'post_id': post.id,
                    'username': request.user.username,
                    'content': post.content,
                    'image_url': post.image.url if post.image else None,
                    'video_url': post.video.url if post.video else None
                })

            return redirect('group_detail', group_id=group.id)
        
    saved_post_ids = []
    if request.user.is_authenticated and is_member and posts:
        try:
            member = Member.objects.get(user=request.user)
            saved_post_ids = list(SavedGroupPost.objects.filter(user=member, post__in=posts).values_list('post_id', flat=True))
        except Member.DoesNotExist:
            pass

    return render(request, 'group_detail.html', {
        'group': group,
        'posts': posts,
        'is_member': is_member,
        'products': products,  # ✅ ส่งสินค้าพร้อมโพสต์ไปยังเทมเพลต
        'saved_post_ids': saved_post_ids,  # ✅ ส่งให้ template ใช้
    })

#โพสต์ในกลุ่ม
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.contrib import messages

@login_required
def create_group_post(request, group_id):
    group = get_object_or_404(CommunityGroup, id=group_id)

    if request.method == "POST":
        content = request.POST.get("content", "").strip()
        image_files = request.FILES.getlist("images")  # ✅ ดึงรูปภาพ
        video_files = request.FILES.getlist("videos")  # ✅ ดึงวิดีโอ
        max_size = 15 * 1024 * 1024  # 15MB

        if content or image_files or video_files:
            post = GroupPost.objects.create(
                group=group,
                user=request.user,
                content=content
            )

            # ✅ เพิ่มการอัปโหลดรูปภาพ
            for img in image_files:
                if isinstance(img, InMemoryUploadedFile) and img.size > max_size:
                    messages.error(request, f"❌ ไฟล์ {img.name} มีขนาดใหญ่เกิน 15MB")
                    continue  
                GroupPostMedia.objects.create(post=post, file=img, media_type="image")

            # ✅ เพิ่มการอัปโหลดวิดีโอ
            for vid in video_files:
                if isinstance(vid, InMemoryUploadedFile) and vid.size > max_size:
                    messages.error(request, f"❌ ไฟล์ {vid.name} มีขนาดใหญ่เกิน 15MB")
                    continue  
                GroupPostMedia.objects.create(post=post, file=vid, media_type="video")

            return redirect('group_detail', group_id=group.id)

    return redirect('group_detail', group_id=group.id)



#เข้าร่วมกลุ่ม
@login_required
def join_group(request, group_id):
    group = get_object_or_404(CommunityGroup, id=group_id)
    if request.user not in group.members.all():
        group.members.add(request.user)
        messages.success(request, "You have joined the group!")
    else:
        messages.info(request, "You are already a member of this group.")
    return redirect('group_detail', group_id=group.id)

#ออกจากกลุ่ม
@login_required
def leave_group(request, group_id):
    """ ให้สมาชิกออกจากกลุ่ม (ยกเว้นผู้สร้างกลุ่ม) """
    group = get_object_or_404(CommunityGroup, id=group_id)

    if request.user == group.creator:
        messages.error(request, "ผู้สร้างกลุ่มไม่สามารถออกจากกลุ่มของตนเองได้!")
    elif request.user in group.members.all():
        group.members.remove(request.user)
        messages.success(request, "คุณได้ออกจากกลุ่มเรียบร้อยแล้ว!")
    else:
        messages.error(request, "คุณไม่ได้เป็นสมาชิกของกลุ่มนี้!")

    return redirect('community_list')



# ไลค์โพสในกลุ่ม
from notifications.utils import create_notification  # ✅ นำเข้า Notification

@login_required
def toggle_group_post_like(request, post_id):
    """
    กดไลค์/เลิกไลค์โพสต์ในกลุ่ม
    """
    post = get_object_or_404(GroupPost, id=post_id)  # ✅ ดึงข้อมูล GroupPost
    user = request.user  

    if post.likes.filter(id=user.id).exists():
        post.likes.remove(user)
        liked = False
    else:
        post.likes.add(user)
        liked = True

        # ✅ FIX: ส่ง `group_post` แทน `post`
        MemberNotification.objects.create(
            user=post.user,  # เจ้าของโพสต์
            # sender=user,  # คนที่กดไลค์
            #notification_type="like_post",
            # group_post=post,  # ✅ ใช้ `group_post` แทน `post`
            message=f"❤️ {user.username} ถูกใจโพสต์ของคุณในกลุ่ม!",
        )

    return JsonResponse({
        'success': True,
        'liked': liked,
        'like_count': post.likes.count(),
    })

#เพิ่มคอมเม้นในกลุ่ม
@login_required
def add_group_post_comment(request, post_id):
    post = get_object_or_404(GroupPost, id=post_id)

    if request.method == "POST":
        try:
            data = json.loads(request.body)  # ✅ อ่าน JSON ที่ส่งมา
            content = data.get("content")

            if content:
                comment = GroupComment.objects.create(post=post, user=request.user, content=content)
                return JsonResponse({
                    "success": True,
                    "comment_id": comment.id,  # ✅ เพิ่มการส่ง comment_id กลับไป
                    "comment": {
                        "user": comment.user.username,
                        "content": comment.content,
                        "created_at": comment.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                    },
                }, status=201)
            return JsonResponse({"success": False, "message": "Comment cannot be empty!"}, status=400)

        except json.JSONDecodeError:
            return JsonResponse({"success": False, "message": "Invalid JSON request!"}, status=400)

    return JsonResponse({"success": False, "message": "Invalid request!"}, status=400)

#ลบคอมเม้นในกลุ่ม
@login_required
def delete_group_comment(request, group_id, comment_id):
    if request.method == "POST":
        comment = get_object_or_404(GroupComment, id=comment_id, post__group_id=group_id)

        # ✅ ตรวจสอบสิทธิ์ของผู้ใช้
        if comment.user != request.user and request.user not in comment.post.group.admins.all():
            return JsonResponse({"success": False, "message": "คุณไม่มีสิทธิ์ลบคอมเมนต์นี้"}, status=403)

        comment.delete()
        return JsonResponse({"success": True, "message": "คอมเมนต์ถูกลบเรียบร้อยแล้ว", "comment_id": comment_id})

    return JsonResponse({"success": False, "message": "Invalid request"}, status=400)



@login_required
def edit_group_comment(request, comment_id):
    comment = get_object_or_404(GroupComment, id=comment_id)

    if request.method == "POST":
        if comment.user != request.user:
            return JsonResponse({"success": False, "message": "คุณไม่มีสิทธิ์แก้ไขคอมเมนต์นี้"}, status=403)

        try:
            data = json.loads(request.body)
            new_content = data.get("content", "").strip()

            if not new_content:
                return JsonResponse({"success": False, "message": "คอมเมนต์ต้องมีข้อความ"}, status=400)

            comment.content = new_content
            comment.save()

            return JsonResponse({
                "success": True,
                "message": "แก้ไขคอมเมนต์สำเร็จ",
                "content": new_content,  # ✅ ส่งเนื้อหาคอมเมนต์กลับไปเพื่ออัปเดตใน frontend
            })
        
        except Exception as e:
            return JsonResponse({"success": False, "message": str(e)}, status=500)

    return JsonResponse({"success": False, "message": "Invalid request"}, status=400)

# แสดงรายละเอียดโพสต์ในกลุ่ม
@login_required
def post_group_detail(request, post_id, group_id):
    """ แสดงรายละเอียดโพสต์ในกลุ่ม """ 
    post = get_object_or_404(GroupPost, id=post_id, group__id=group_id)  # ✅ ใช้ group__id
    group = post.group  # ✅ ดึงกลุ่มจากโพสต์โดยตรง
    return render(request, 'post_group_detail.html', {
        'post': post,
        'group': group  # ✅ ส่ง group ไป template
    })


#อัพเดทโปรไฟล์
from .forms import AccountEditForm, PasswordChangeForm, ProfileUpdateForm
@login_required
def profile_management(request):
    user = request.user
    profile, created = Member.objects.get_or_create(user=user)  # ✅ แก้ให้ถูกต้อง

    if request.method == "POST":
        if "update_personal_info" in request.POST:
            form = ProfileUpdateForm(request.POST, request.FILES, instance=profile)
            if form.is_valid():
                form.save()
                messages.success(request, "✅ ข้อมูลส่วนตัวของคุณถูกบันทึกเรียบร้อยแล้ว!")
                return redirect("profile_management")

        elif "change_password" in request.POST:
            password_form = CustomPasswordChangeForm(user, request.POST)
            if password_form.is_valid():
                user = password_form.save()
                update_session_auth_hash(request, user)  
                messages.success(request, "🔒 รหัสผ่านถูกเปลี่ยนเรียบร้อยแล้ว!")
                return redirect("profile_management")

    else:
        form = ProfileUpdateForm(instance=profile)
        password_form = CustomPasswordChangeForm(user)

    return render(request, "profile_management.html", {
        "form": form,
        "password_form": password_form,
    })

# แสดงโปรไฟล์ผู้ใช้
@login_required
def profile_view(request, user_id):

    products = Product.objects.all()[:6]  

    user = get_object_or_404(CustomUser, pk=user_id)
    posts = Post.objects.filter(user=user)
    
    # ตรวจสอบว่าเป็นโปรไฟล์ของผู้ที่ล็อกอินหรือไม่
    is_own_profile = request.user == user
    is_following = user.followers.filter(id=request.user.id).exists()
    
    context = {
        'user': user,
        'posts': posts,
        'is_own_profile': is_own_profile,
        'is_following': is_following,
        'products': products,  # ส่งสินค้าพร้อมโพสต์ไปยังเทมเพลต
    }
    return render(request, 'profile.html', context)

# แชร์โพสต์หน้าหลัก
@login_required
def share_post(request, post_id):
    """ ฟังก์ชันแชร์โพสต์ """
    if request.method == "POST":
        original_post = get_object_or_404(Post, id=post_id)

        # ✅ สร้างโพสต์ใหม่ที่ลิงก์ไปยังโพสต์ต้นฉบับ
        shared_post = Post.objects.create(
            user=request.user,
            content=f"📢 Shared from {original_post.user.username}:\n{original_post.content}",
            shared_from=original_post
        )

        # ✅ คัดลอกไฟล์สื่อจากโพสต์ต้นฉบับ
        for media in original_post.media.all():  # ✅ ใช้ `.all` (ไม่มีวงเล็บ)
            PostMedia.objects.create(
                post=shared_post, 
                file=media.file, 
                media_type=media.media_type
            )

        # ✅ ตรวจสอบว่าคำขอเป็น AJAX หรือไม่
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'success': True, 'message': "โพสต์ถูกแชร์แล้ว!", 'post_id': shared_post.id}, status=201)

        return redirect(request.META.get('HTTP_REFERER', 'home'))  # ✅ กลับไปหน้าที่แชร์

    return JsonResponse({'success': False, 'message': 'Invalid request'}, status=400)

# บันทึกโพสต์ในกลุ่ม
@login_required
def save_group_post(request, group_id, post_id):
    """ บันทึก/ลบโพสต์ในกลุ่มจากรายการบันทึก """
    group = get_object_or_404(CommunityGroup, id=group_id)  # ดึงข้อมูลกลุ่ม
    post = get_object_or_404(GroupPost, id=post_id)  # ดึงโพสต์

    try:
        member = Member.objects.get(user=request.user)  # ✅ ดึง `Member` instance
    except Member.DoesNotExist:
        return JsonResponse({"success": False, "message": "Member profile not found"}, status=400)

    # ใช้ filter เพื่อดึงรายการที่ตรงกับเงื่อนไข
    saved_posts = SavedGroupPost.objects.filter(user=member, post=post)

    # ถ้ามีมากกว่าหนึ่งรายการ ให้ลบรายการที่เกิน
    if saved_posts.count() > 1:
        saved_posts.exclude(id=saved_posts.first().id).delete()

    # ตรวจสอบว่ามีการบันทึกโพสต์แล้วหรือยัง
    if saved_posts.exists():
        saved_post = saved_posts.first()
        saved_post.delete()
        saved = False
    else:
        saved_post = SavedGroupPost.objects.create(user=member, post=post)
        saved = True

    return JsonResponse({
        "success": True,
        "saved": saved,
        "save_count": SavedGroupPost.objects.filter(post=post).count(),
    }, status=200)


# ลบโพสต์ในกลุ่มจากรายการบันทึก
@login_required
def remove_saved_group_post(request, group_id, post_id):
    """ ฟังก์ชันลบโพสต์จาก Saved List (โพสต์ในกลุ่ม) """
    group = get_object_or_404(CommunityGroup, id=group_id)  # ดึงข้อมูลกลุ่ม
    post = get_object_or_404(GroupPost, id=post_id, group=group)  # ดึงโพสต์ในกลุ่มที่ตรงกับ group_id

    try:
        member = Member.objects.get(user=request.user)  # ดึง `Member` instance
    except Member.DoesNotExist:
        return JsonResponse({"success": False, "message": "Member profile not found"}, status=400)

    try:
        # ลบโพสต์จากรายการบันทึกของกลุ่มที่เป็นของสมาชิก
        saved_post = SavedGroupPost.objects.get(user=member, post=post)
        saved_post.delete()  # ลบโพสต์จากรายการบันทึก
        return JsonResponse({'success': True, 'message': 'Group post removed from saved list'}, status=200)
    except SavedGroupPost.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Group post not found in saved list'}, status=404)


# แชร์โพสต์ไปยังกลุ่มที่เลือก
@login_required
def share_group_post(request, group_id, post_id):
    if request.method != "POST":
        return JsonResponse({'success': False, 'error': 'Invalid method'}, status=405)

    post = get_object_or_404(GroupPost, id=post_id)
    target_group = get_object_or_404(CommunityGroup, id=group_id)  # ✅ ใช้ group_id ที่ส่งมา

    # สร้างโพสต์ใหม่ในกลุ่มที่กำหนด
    shared_post = GroupPost.objects.create(
        group=target_group,
        user=request.user,
        content=f"📢 Shared from {post.user.username}: {post.content}",
        shared_from=post  # ถ้ามี field shared_from
    )

    # คัดลอกสื่อ
    for media in post.media.all():
        GroupPostMedia.objects.create(
            post=shared_post, 
            file=media.file,
            media_type=media.media_type
        )

    return JsonResponse({
        'success': True,
        'message': "โพสต์ถูกแชร์ไปยังกำหนดแล้ว!",
        'post_id': shared_post.id
    }, status=201)




# แก้ไขโพสต์ในกลุ่ม
# @login_required
# def edit_group_post(request, post_id):
#     post = get_object_or_404(GroupPost, id=post_id, user=request.user)

#     if request.method == "POST":
#         content = request.POST.get("content", "").strip()
#         images = request.FILES.getlist("images")
#         videos = request.FILES.getlist("videos")

#         # ✅ อัปเดตเนื้อหาโพสต์
#         post.content = content
#         post.save()

#         # ✅ ลบไฟล์ที่ผู้ใช้เลือก
#         delete_media_ids = request.POST.getlist("delete_media")
#         GroupPostMedia.objects.filter(id__in=delete_media_ids, post=post).delete()

#         # ✅ เพิ่มไฟล์ใหม่
#         for image in images:
#             GroupPostMedia.objects.create(post=post, file=image, media_type="image")

#         for video in videos:
#             GroupPostMedia.objects.create(post=post, file=video, media_type="video")

#         return redirect('group_post_detail', post_id=post.id)

# แก้ไขโพสต์ในกลุ่ม
@login_required
def group_edit_post(request, post_id):
    """ ฟังก์ชันแก้ไขโพสต์ในกลุ่ม """
    post = get_object_or_404(GroupPost, id=post_id)

    # ✅ ตรวจสอบว่าเป็นเจ้าของโพสต์หรือไม่
    if post.user != request.user:
        return redirect('community_list')  # ✅ ส่งกลับไปหน้าชุมชนถ้าไม่ใช่เจ้าของโพสต์

    if request.method == "POST":
        form = EditPostForm(request.POST, instance=post)

        if form.is_valid():
            form.save()

            # ✅ ดึงไฟล์รูปภาพและวิดีโอที่อัปโหลดใหม่
            images = request.FILES.getlist("images")
            videos = request.FILES.getlist("videos")

            for file in images:
                GroupPostMedia.objects.create(post=post, file=file, media_type='image')

            for file in videos:
                GroupPostMedia.objects.create(post=post, file=file, media_type='video')

            # ✅ กลับไปที่หน้ากลุ่มหลังจากแก้ไขเสร็จ
            return redirect('group_detail', group_id=post.group.id)

    else:
        form = EditPostForm(instance=post)

    return render(request, "group_edit_post.html", {"form": form, "post": post})

#ลบโพสต์ในกลุ่ม
from django.http import JsonResponse, HttpResponseForbidden
def delete_group_post(request, group_id, post_id):
    if request.method == "POST":
        try:
            print(f"Debug: group_id={group_id}, post_id={post_id}, user={request.user}")  # ✅ Debugging

            post = get_object_or_404(GroupPost, id=post_id, group_id=group_id)

            if post.user != request.user:
                return JsonResponse({'success': False, 'message': 'คุณไม่มีสิทธิ์ลบโพสต์นี้'}, status=403)

            post.delete()
            return JsonResponse({'success': True, 'message': 'โพสต์ถูกลบเรียบร้อยแล้ว'})
        
        except Exception as e:
            return JsonResponse({'success': False, 'message': str(e)}, status=500)

    return HttpResponseForbidden("Method not allowed")

@login_required
def seller_dashboard(request):
    # ✅ ป้องกันไม่ให้ user ที่ไม่ใช่ seller เข้ามา
    if not hasattr(request.user, 'seller_profile') or request.user.role != 'seller':
        raise PermissionDenied("คุณไม่มีสิทธิ์เข้าถึงหน้านี้")

    seller = request.user.seller_profile
    products = seller.products.all()
    total_products = products.count()

    valid_orders = OrderItem.objects.filter(
        order__seller=seller,
        order__status='delivered'
    ).exclude(
        refund_requests__status='approved'
    )

    total_earnings_data = valid_orders.annotate(
        item_total=ExpressionWrapper(F('quantity') * F('price_per_item'), output_field=DecimalField())
    ).aggregate(total=Sum('item_total'))
    total_earnings = total_earnings_data['total'] or 0

    product_sales = valid_orders.values("product__id").annotate(
        total_sold_count=Sum("quantity")
    )
    sales_dict = {item["product__id"]: item["total_sold_count"] for item in product_sales}
    for product in products:
        product.sales_count = sales_dict.get(product.id, 0)

    return render(request, "seller_dashboard.html", {
        "products": products,
        "seller": seller,
        "total_products": total_products,
        "total_earnings": total_earnings,
    })

@login_required
def add_product(request):
    """ เพิ่มสินค้าใหม่ """
    seller = request.user.seller_profile
    if request.method == "POST":
        form = ProductForm(request.POST, request.FILES)
        if form.is_valid():
            product = form.save(commit=False)
            product.seller = seller
            product.save()
            messages.success(request, "Product added successfully!")
            return redirect("seller_dashboard")
    else:
        form = ProductForm()
    return render(request, "add_product.html", {"form": form})

#@login_required
#def edit_product(request, product_id):
    #""" แก้ไขสินค้า """
   # product = get_object_or_404(Product, id=product_id, seller=request.user.seller_profile)
   # if request.method == "POST":
      #  form = ProductForm(request.POST, request.FILES, instance=product)
      #  if form.is_valid():
      #      form.save()
      #      messages.success(request, "Product updated successfully!")
      #      return redirect("seller_dashboard")
  #  else:
    #    form = ProductForm(instance=product)
   # return render(request, "edit_product.html", {"form": form})

# ✅ ฟังก์ชันลบสินค้า
@login_required
def delete_product(request, product_id):
    """ ลบสินค้า """
    product = get_object_or_404(Product, id=product_id, seller=request.user.seller_profile)
    product.delete()
    messages.success(request, "Product deleted successfully!")
    return redirect("seller_dashboard")


# ✅ ฟังก์ชันสำหรับ Seller Login
def seller_login(request):
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]

        user = authenticate(request, username=username, password=password)

        if user is not None:
            if hasattr(user, 'seller_profile'):  # ✅ เช็คว่าผู้ใช้เป็น Seller หรือไม่
                login(request, user)
                return redirect("seller_dashboard")  # ✅ ไปที่หน้าหลักของ Seller
            else:
                messages.error(request, "คุณไม่ใช่ผู้ขาย")
        else:
            messages.error(request, "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง")

    return render(request, "seller_login.html")

# ✅ ฟังก์ชันสำหรับ Seller Logout
@login_required
def seller_logout(request):
    logout(request)
    messages.success(request, "คุณได้ออกจากระบบเรียบร้อยแล้ว")
    return redirect("seller_login")

from django.contrib.auth import get_user_model
from django.contrib.auth import login
from django.conf import settings

User = get_user_model()  # ใช้ CustomUser

def register_seller(request):
    if request.method == "POST":
        user_form = CustomUserCreationForm(request.POST)
        seller_form = SellerForm(request.POST, request.FILES)

        if user_form.is_valid() and seller_form.is_valid():
            username = user_form.cleaned_data.get("username")
            if User.objects.filter(username=username).exists():
                messages.error(request, "⚠️ ชื่อผู้ใช้นี้ถูกใช้แล้ว กรุณาเลือกชื่ออื่น!")
            else:
                user = user_form.save(commit=False)
                user.role = 'seller'
                user.save()

                user.backend = settings.AUTHENTICATION_BACKENDS[0]

                if not seller_form.cleaned_data.get("store_image"):
                    messages.error(request, "⚠️ กรุณาอัปโหลดรูปภาพร้านค้าก่อนสมัคร!")
                    return render(request, "register_seller.html", {
                        "user_form": user_form,
                        "seller_form": seller_form
                    })

                seller = seller_form.save(commit=False)
                seller.user = user
                seller.email = user.email
                seller.save()

                # ✅ เปลี่ยนเส้นทางไปหน้า login แทน
                messages.success(request, "🎉 สมัครเป็นผู้ขายสำเร็จ! กรุณาเข้าสู่ระบบเพื่อต่อไป!")
                return redirect("seller_login")

        else:
            password1 = request.POST.get("password1")
            if len(password1) < 8:
                messages.error(request, "⚠️ รหัสผ่านต้องมีอย่างน้อย 8 ตัวอักษร!")
            if password1.isnumeric():
                messages.error(request, "⚠️ รหัสผ่านต้องไม่เป็นตัวเลขทั้งหมด!")
            if password1.isalpha():
                messages.error(request, "⚠️ รหัสผ่านต้องมีทั้งตัวอักษรและตัวเลข!")

    else:
        user_form = CustomUserCreationForm()
        seller_form = SellerForm()

    return render(request, "register_seller.html", {
        "user_form": user_form,
        "seller_form": seller_form
    })

# ✅ แสดงสินค้าทั้งหมด (สำหรับลูกค้าและผู้ขาย)
@login_required
def product_list(request):
    """ แสดงสินค้าทั้งหมด พร้อมการค้นหา """
    if request.user.role != 'member':
        messages.error(request, "❌ เฉพาะสมาชิกเท่านั้น!")
        return redirect('login')

    query = request.GET.get('search', '')
    category_filter = request.GET.get('category', '')

    products = Product.objects.all()

    if query:
        products = products.filter(
            Q(name__icontains=query) | Q(description__icontains=query) | Q(category__icontains=query)
        )

    if category_filter:
        products = products.filter(category=category_filter)

    return render(request, "product_list.html", {"products": products, "query": query, "category_filter": category_filter})


@login_required
def my_products(request):
    # ✅ ตรวจสอบว่าเป็นผู้ขายจริงหรือไม่
    if not hasattr(request.user, 'seller_profile') or request.user.role != 'seller':
        raise PermissionDenied("คุณไม่มีสิทธิ์เข้าถึงหน้านี้")

    # ✅ ดึง seller profile
    seller = get_object_or_404(Seller, user=request.user)

    # ✅ ดึงสินค้าทั้งหมดของผู้ขาย
    products = Product.objects.filter(seller=seller)

    # ✅ คำนวณยอดรวมสินค้า และยอดขายรวม
    total_products = products.count()
    total_earnings = sum(p.price * p.total_sold for p in products)

    context = {
        'seller': seller,
        'store': seller,
        'products': products,
        'total_products': total_products,
        'total_earnings': total_earnings,
    }

    return render(request, 'my_products.html', context)


@login_required
def edit_product(request, product_id):
    """ แก้ไขสินค้าสำหรับผู้ขายหรือแอดมิน """
    product = get_object_or_404(Product, id=product_id)

    # ✅ ตรวจสอบสิทธิ์: ผู้ขายของสินค้า หรือ แอดมิน
    if product.seller.user != request.user and not request.user.is_superuser:
        messages.error(request, "❌ คุณไม่มีสิทธิ์ในการแก้ไขสินค้านี้")
        return redirect(request.META.get('HTTP_REFERER', 'seller_dashboard'))

    if request.method == 'POST':
        form = ProductForm(request.POST, request.FILES, instance=product)
        if form.is_valid():
            form.save()
            messages.success(request, "✅ แก้ไขสินค้าเรียบร้อยแล้ว!")

            # ✅ ตรวจสอบ URL ก่อนหน้า
            referer = request.META.get('HTTP_REFERER', '')
            if 'seller_dashboard' in referer:
                return redirect('seller_dashboard')
            elif 'my_products' in referer:
                return redirect('my_products')
            else:
                return redirect('seller_dashboard')  # ค่าเริ่มต้น
    else:
        form = ProductForm(instance=product)

    return render(request, 'edit_product.html', {'form': form, 'product': product})
# ✅ แสดงรายละเอียดสินค้า
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from .models import Product, Review
from .services import analyze_text

# ✅ แสดงรายละเอียดสินค้า
@login_required
def product_detail(request, product_id):
    if not request.user.is_authenticated or request.user.role != 'member':
        messages.error(request, "❌ เฉพาะสมาชิก (Member) เท่านั้นที่สามารถเข้าถึงหน้านี้ได้")
        return redirect('login')  # หรือเปลี่ยนเส้นทางไปหน้าที่เหมาะสม เช่น 'home'
    product = get_object_or_404(Product, id=product_id)
    reviews = Review.objects.filter(product=product)
    review_responses = {r.review_id: r for r in ReviewResponse.objects.filter(review__product=product)}


    # ✅ แปลงคะแนนรีวิวเป็นดาว ⭐⭐⭐⭐⭐
    for review in reviews:
        review.stars = ['⭐' for _ in range(review.rating)]

    # ✅ เช็คหากผู้ใช้กดปุ่มวิเคราะห์รีวิว
    if request.method == "POST":
        reviews_to_analyze = reviews.filter(analysis_done=False)
        count = 0
        updates = []

        for review in reviews_to_analyze:
            sentiment = analyze_text(review.comment)
            if sentiment:  # ✅ เช็คว่าผลลัพธ์ถูกต้อง
                review.sentiment = sentiment
                review.analysis_done = True
                updates.append(review)
                count += 1

        # ✅ ใช้ bulk update ลดจำนวน query
        if updates:
            Review.objects.bulk_update(updates, ["sentiment", "analysis_done"])
            messages.success(request, f'✅ วิเคราะห์รีวิว {count} รายการสำเร็จ')
        else:
            messages.warning(request, '⚠️ ไม่มีรีวิวใหม่ที่ต้องวิเคราะห์')


    # ✅ คำนวณสัดส่วนรีวิวแต่ละประเภท
    total_reviews = reviews.count()
    positive_count = reviews.filter(sentiment="positive").count()
    neutral_count = reviews.filter(sentiment="neutral").count()
    negative_count = reviews.filter(sentiment="negative").count()

    if total_reviews > 0:
        positive_ratio = (positive_count / total_reviews) * 100
        neutral_ratio = (neutral_count / total_reviews) * 100
        negative_ratio = (negative_count / total_reviews) * 100
    else:
        positive_ratio = neutral_ratio = negative_ratio = 0


    return render(request, 'product_detail.html', {
        'product': product,
        'reviews': reviews,
        'positive_ratio': positive_ratio,
        'neutral_ratio': neutral_ratio,
        'negative_ratio': negative_ratio,
        "review_responses": review_responses,
    })

@login_required
def product_detail_user(request, product_id):
    product = get_object_or_404(Product, id=product_id)
    reviews = Review.objects.filter(product=product)  # ดึงรีวิวของสินค้า

    return render(request, 'product_detail_user.html', {
        'product': product,
        'reviews': reviews
    })

@login_required
def delete_product(request, product_id):
    """ ลบสินค้าสำหรับผู้ขายหรือแอดมิน """
    product = get_object_or_404(Product, id=product_id)

    # ✅ ตรวจสอบสิทธิ์: ผู้ขายของสินค้า หรือ แอดมิน
    if product.seller.user == request.user or request.user.is_superuser:
        product.delete()
        messages.success(request, "✅ ลบสินค้าเรียบร้อยแล้ว!")
    else:
        messages.error(request, "❌ คุณไม่มีสิทธิ์ในการลบสินค้านี้")

    # ✅ ตรวจสอบ URL ก่อนหน้า
    referer = request.META.get('HTTP_REFERER', '')

    # ✅ ใช้คำค้นหาเพื่อกำหนดการรีไดเรกต์
    if 'seller_dashboard' in referer:
        return redirect('seller_dashboard')
    elif 'my_products' in referer:
        return redirect('my_products')
    else:
        return redirect('seller_dashboard')  # ค่าเริ่มต้นเป็นหน้าแดชบอร์ด


@login_required
def edit_seller_profile(request):
    """ แก้ไขโปรไฟล์ผู้ขาย + อัปเดตรหัสผ่าน """
    
    user = request.user  # ดึงข้อมูลผู้ใช้ที่ล็อกอิน
    seller = get_object_or_404(Seller, user=user)  # ดึงข้อมูลร้านค้าของผู้ใช้

    # ✅ กำหนดค่าเริ่มต้นให้ user_form และ seller_form
    user_form = CustomUserUpdateForm(instance=user)
    seller_form = SellerProfileUpdateForm(instance=seller)
    password_form = PasswordChangeForm(user)

    if request.method == "POST":
        # ✅ อัปเดตโปรไฟล์ผู้ใช้
        if "update_profile" in request.POST:
            user_form = CustomUserUpdateForm(request.POST, instance=user)
            seller_form = SellerProfileUpdateForm(request.POST, request.FILES, instance=seller)

            if user_form.is_valid() and seller_form.is_valid():
                user_form.save()
                seller_form.save()
                messages.success(request, "✅ โปรไฟล์ของคุณได้รับการอัปเดตแล้ว!")
                return redirect(request.path)  # ✅ กลับมาหน้าเดิม

        # ✅ อัปเดตรหัสผ่าน
        elif "change_password" in request.POST:
            password_form = PasswordChangeForm(user, request.POST)
            if password_form.is_valid():
                user = password_form.save()
                update_session_auth_hash(request, user)  # ป้องกันไม่ให้ต้องล็อกอินใหม่
                messages.success(request, "🔑 รหัสผ่านของคุณถูกเปลี่ยนเรียบร้อยแล้ว!")
                return redirect(request.path)  # ✅ กลับมาหน้าเดิม
            else:
                messages.error(request, "❌ โปรดตรวจสอบข้อมูลที่ป้อน")

    return render(request, "edit_seller_profile.html", {
        "user_form": user_form,
        "seller_form": seller_form,
        "password_form": password_form
    })

@login_required
def edit_store(request):
    """ ฟังก์ชันสำหรับแก้ไขข้อมูลร้านค้า """
    seller = get_object_or_404(Seller, user=request.user)

    if request.method == 'POST':
        form = SellerUpdateForm(request.POST, request.FILES, instance=seller)
        if form.is_valid():
            form.save()
            messages.success(request, "✅ ข้อมูลร้านค้าของคุณถูกอัปเดตเรียบร้อยแล้ว!")
            return redirect('seller_dashboard')  # กลับไปยังแดชบอร์ดของผู้ขาย
    else:
        form = SellerUpdateForm(instance=seller)

    return render(request, 'edit_store.html', {'form': form})

# ✅ แสดงหน้าตะกร้าสินค้า
@login_required
def view_cart(request):
    cart, created = Cart.objects.get_or_create(user=request.user)
    cart_items = CartItem.objects.filter(cart=cart)
    total_price = sum(item.quantity * item.product.price for item in cart_items)

    return render(request, 'cart.html', {
        'cart_items': cart_items,
        'total_price': total_price
    })
@login_required
def product_detail_user(request, product_id):
    # ดึงข้อมูลสินค้าที่มีรีวิว
    product = Product.objects.get(id=product_id)
    reviews = Review.objects.filter(product=product)

    product = get_object_or_404(Product, id=product_id)
    reviews = Review.objects.filter(product=product)  # ดึงรีวิวของสินค้า

    return render(request, 'product_detail_user.html', {
        'product': product,
        'reviews': reviews,
    })

# ✅ แสดงรายละเอียดร้านค้า
def store_detail(request, store_id):
    store = Seller.objects.get(id=store_id)
    products = store.products.all()  # ดึงสินค้าทั้งหมดของร้านค้า
    return render(request, 'store_detail.html', {'store': store, 'products': products})

@login_required
@csrf_exempt  # ✅ ใช้ @csrf_exempt สำหรับ AJAX (แต่ควรใช้ CSRF Token ดีกว่า)
def add_to_cart(request, product_id):
    """ ✅ เพิ่มสินค้าลงตะกร้าแบบ AJAX """
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            product_id = data.get("product_id")

            if not request.user.is_authenticated:
                return JsonResponse({"success": False, "message": "กรุณาเข้าสู่ระบบก่อน"}, status=401)

            product = get_object_or_404(Product, id=product_id)

            if product.stock <= 0:
                return JsonResponse({"success": False, "message": "❌ สินค้าหมด"}, status=400)

            cart, created = Cart.objects.get_or_create(user=request.user)
            cart_item, created = CartItem.objects.get_or_create(cart=cart, product=product)

            if not created:
                cart_item.quantity += 1
                cart_item.save()

            cart_count = sum(item.quantity for item in cart.cartitem_set.all())

            return JsonResponse({"success": True, "cart_count": cart_count})

        except Exception as e:
            return JsonResponse({"success": False, "message": str(e)}, status=500)

    return JsonResponse({"success": False, "message": "Method Not Allowed"}, status=405)

def add_to_cart_ajax(request, product_id):
    if request.method == "POST":
        if not request.user.is_authenticated:
            return JsonResponse({"success": False, "message": "กรุณาเข้าสู่ระบบก่อน"})

        product = get_object_or_404(Product, id=product_id)
        cart, created = Cart.objects.get_or_create(user=request.user)
        cart_item, created = CartItem.objects.get_or_create(cart=cart, product=product)

        if not created:
            cart_item.quantity += 1
            cart_item.save()

        cart_count = CartItem.objects.filter(cart=cart).count()
        return JsonResponse({"success": True, "cart_count": cart_count})

    return JsonResponse({"success": False, "message": "Invalid request"})

def update_cart(request, item_id, action):
    cart_item = CartItem.objects.get(id=item_id)
    product = cart_item.product

    if action == 'increase':
        # ตรวจสอบสต๊อกสินค้า
        if product.stock >= cart_item.quantity + 1:
            cart_item.quantity += 1
            cart_item.save()
        else:
            return JsonResponse({"success": False, "error": "ไม่มีสินค้าพอในสต๊อก"})
    elif action == 'decrease':
        if cart_item.quantity > 1:
            cart_item.quantity -= 1
            cart_item.save()
        else:
            return JsonResponse({"success": False, "error": "จำนวนสินค้าต่ำสุดไม่สามารถลดลงได้"})

    # คำนวณราคาใหม่
    new_total = cart_item.quantity * product.price
    cart_total = sum([item.quantity * item.product.price for item in cart_item.cart.cartitem_set.all()])

    return JsonResponse({
        "success": True,
        "new_quantity": cart_item.quantity,
        "new_total": new_total,
        "cart_total": cart_total,
    })
@login_required
def remove_from_cart(request, item_id):
    """ ลบสินค้าออกจากตะกร้า """
    cart_item = get_object_or_404(CartItem, id=item_id, cart__user=request.user)
    cart_item.delete()

    return JsonResponse({"success": True, "cart_total": get_cart_total(request.user)})

def get_cart_total(user):
    """ คำนวณราคาทั้งหมดของตะกร้า """
    total = sum(item.total_price() for item in CartItem.objects.filter(cart__user=user))
    return total

@login_required
def update_shipping(request):
    """ อัปเดตที่อยู่จัดส่ง """
    if request.method == "POST":
        address = request.POST.get("address")
        city = request.POST.get("city")  # ✅ ดึงค่า city
        postal_code = request.POST.get("postal_code")  # ✅ ดึงค่า postal_code
        phone = request.POST.get("phone_number")

        shipping, created = ShippingAddress.objects.get_or_create(user=request.user)
        shipping.address = address
        shipping.city = city  # ✅ บันทึก city
        shipping.postal_code = postal_code  # ✅ บันทึก postal_code
        shipping.phone_number = phone
        shipping.save()

        messages.success(request, "✅ อัปเดตที่อยู่จัดส่งเรียบร้อย!")
        return redirect('checkout')

    return render(request, "shipping_form.html")


@login_required
def upload_payment(request, order_ids):
    """ อัปโหลดหลักฐานการชำระเงิน และอัปเดตสถานะออเดอร์ """
    order_ids = [int(id) for id in order_ids.split(",")]
    orders = Order.objects.filter(id__in=order_ids, user=request.user)

    total_payment = sum(order.total_price for order in orders)  # ✅ รวมยอดเงินที่ต้องชำระ

    if request.method == "POST":
        payment_slip = request.FILES.get("slip")
        if not payment_slip:
            messages.error(request, "⚠️ กรุณาอัปโหลดสลิป!")
            return redirect("upload_payment", order_ids=order_ids)

        for order in orders:
            # ✅ ตรวจสอบว่ามี Payment อยู่แล้วหรือไม่
            payment, created = Payment.objects.get_or_create(
                order=order,
                defaults={
                    "user": request.user,
                    "amount": order.total_price,
                    "slip": payment_slip,
                }
            )
            if not created:
                payment.slip = payment_slip  # อัปเดตสลิปใหม่ถ้ามีอยู่แล้ว
                payment.save()

            order.payment_status = "pending"  # ✅ เปลี่ยนเป็น "รอยืนยันการชำระ"
            order.save()

        messages.success(request, "✅ ชำระเงินสำเร็จ! กรุณารอการตรวจสอบจากผู้ขาย")
        return redirect('order_history')

    return render(request, "upload_payment.html", {"orders": orders, "total_payment": total_payment})

@login_required
def add_review(request, order_id, product_id):
    """ ✅ ให้รีวิวสินค้าได้เฉพาะเมื่อออเดอร์จัดส่งสำเร็จ และไม่สามารถรีวิวซ้ำได้ """
    
    # ตรวจสอบออเดอร์ที่จัดส่งสำเร็จ
    order = get_object_or_404(Order, id=order_id, user=request.user, status="delivered")
    product = get_object_or_404(Product, id=product_id)

    # 🔍 Debugging
    print(f"🔍 DEBUG: order_id -> {order_id}, product_id -> {product_id}")
    print(f"🔍 DEBUG: Order Exists? {order is not None}")
    print(f"🔍 DEBUG: Product Exists? {product is not None}")

    # ✅ ตรวจสอบว่าผู้ใช้เคยรีวิวสินค้านี้ไปแล้วหรือไม่
    if Review.objects.filter(user=request.user, product=product, order=order).exists():
        messages.warning(request, "❌ คุณได้รีวิวสินค้านี้ไปแล้ว")
        return redirect("product_detail", product_id=product.id)

    if request.method == "POST":
        rating = request.POST.get("rating")
        comment = request.POST.get("comment")
        media_files = request.FILES.getlist("media")

        if not rating or not comment:
            messages.error(request, "❌ กรุณาให้คะแนนและเขียนรีวิวก่อนส่ง")
            return render(request, "add_review.html", {"product": product, "order": order})

        # ✅ บันทึกรีวิว
        review = Review.objects.create(
            user=request.user, 
            product=product, 
            order=order,  
            rating=int(rating), 
            comment=comment
        )

        # ✅ บันทึกไฟล์แนบ (ภาพ/วิดีโอ)
        for file in media_files:
            media_type = "image" if file.content_type.startswith("image") else "video"
            ReviewMedia.objects.create(review=review, file=file, media_type=media_type)

        # ✅ ตรวจสอบว่าเจ้าของร้านมีอยู่จริงก่อนแจ้งเตือน
        if product.seller:
            print(f"🛎 กำลังสร้างแจ้งเตือนให้ {product.seller.user.username} ...")  # ✅ Debugging

        messages.success(request, "✅ รีวิวของคุณถูกบันทึกเรียบร้อย!")
        return redirect("product_detail", product_id=product.id)

    return render(request, "add_review.html", {"product": product, "order": order})




@login_required
def order_tracking(request):
    """ ดูสถานะการสั่งซื้อ """
    orders = Order.objects.filter(user=request.user)
    return render(request, "order_tracking.html", {"orders": orders})

@login_required
def checkout(request):
    """ แสดงหน้าสรุปออเดอร์ก่อนยืนยัน และเลือกที่อยู่จัดส่ง """
    cart = Cart.objects.get(user=request.user)
    cart_items = CartItem.objects.filter(cart=cart)

    if not cart_items:
        messages.error(request, "❌ ไม่มีสินค้าในตะกร้า กรุณาเลือกสินค้าก่อนทำการสั่งซื้อ!")
        return redirect('cart')  # กลับไปหน้า Cart

    # แยกสินค้าออกเป็นออเดอร์ตามร้านค้า
    orders_by_seller = {}
    total_checkout_price = 0  

    for item in cart_items:
        seller = item.product.seller
        if seller not in orders_by_seller:
            orders_by_seller[seller] = []
        orders_by_seller[seller].append(item)
        total_checkout_price += item.quantity * item.product.price

    # ✅ ดึงที่อยู่ของผู้ใช้ทั้งหมด
    saved_addresses = ShippingAddress.objects.filter(user=request.user)

    return render(request, "checkout.html", {
        "orders_by_seller": orders_by_seller,
        "total_checkout_price": total_checkout_price,
        "saved_addresses": saved_addresses,  # ✅ ส่งที่อยู่ทั้งหมดไปยัง Template
    })

@login_required
def return_order(request, order_id):
    """ ฟังก์ชันขอคืนสินค้าหรือยกเลิกออเดอร์ """
    order = get_object_or_404(Order, id=order_id, user=request.user)

    if order.status == "Completed":
        messages.error(request, "❌ ไม่สามารถคืนสินค้าหลังจากส่งสำเร็จแล้ว!")
        return redirect('order_tracking')

    if request.method == "POST":
        reason = request.POST.get("reason", "").strip()
        if not reason:
            messages.error(request, "❌ กรุณากรอกเหตุผลการคืนสินค้า!")
            return redirect('return_order', order_id=order.id)

        order.status = "Return Requested"
        order.return_reason = reason
        order.save()

        messages.success(request, "✅ คำขอคืนสินค้าของคุณถูกส่งแล้ว!")
        return redirect('order_tracking')

    return render(request, "return_order.html", {"order": order})

@login_required
@csrf_exempt  # ✅ ปิดการตรวจสอบ CSRF ชั่วคราว (ใช้เฉพาะทดสอบ)
@login_required
def cancel_order(request, order_id):
    """ แสดงฟอร์มให้ผู้ใช้กรอกเหตุผลก่อนยกเลิกออเดอร์ """
    order = get_object_or_404(Order, id=order_id, user=request.user)

    if request.method == "POST":
        reason = request.POST.get("reason", "").strip()
        if not reason:
            messages.error(request, "❌ กรุณากรอกเหตุผลก่อนยกเลิกออเดอร์!")
            return render(request, "cancel_order.html", {"order": order})  

        # ✅ เปลี่ยนสถานะออเดอร์เป็น "ยกเลิกแล้ว"
        order.status = "cancelled"
        order.cancel_reason = reason
        order.save()

        messages.success(request, f"✅ ออเดอร์ #{order.id} ถูกยกเลิกเรียบร้อยแล้ว!")
        return redirect("order_history")  # กลับไปยังหน้าประวัติคำสั่งซื้อ

    return render(request, "cancel_order.html", {"order": order})



# @login_required
# def order_history(request):
#     """ แสดงประวัติคำสั่งซื้อของผู้ใช้ """
#     orders = Order.objects.filter(user=request.user).order_by('-created_at')
#     pending_orders = orders.filter(status__in=["pending", "processing", "shipped"])
#     completed_orders = orders.filter(status="delivered")

#     context = {
#         'orders': orders,
#         'pending_orders': pending_orders,
#         'completed_orders': completed_orders,
#     }
#     return render(request, 'order_history.html', context)

@login_required
def refund_history(request):
    """ แสดงประวัติการคืนเงินของผู้ใช้ """
    return_orders = RefundRequest.objects.filter(
        user=request.user, status="refunded", confirmed_by_user=False
    ).select_related('order', 'item', 'item__product')

    context = {
        'return_orders': return_orders,
    }
    return render(request, 'refund_history.html', context)


@login_required
def order_history(request):
    orders = Order.objects.filter(user=request.user).order_by('-created_at')
    pending_orders = orders.filter(status__in=["pending", "processing", "shipped"])
    completed_orders = orders.filter(status="delivered").exclude(status="refunded")
    cancelled_orders = orders.filter(status="cancelled")
    return_orders = RefundRequest.objects.filter(user=request.user)

    reviewed_products = {}

    # ✅ ดึงสินค้าที่ถูกรีวิวแล้วและแปลงเป็น dict
    reviewed_products = Review.objects.filter(user=request.user).values_list("product_id", "order_id")
    reviewed_dict = {str(f"{product_id}_{order_id}"): True for product_id, order_id in reviewed_products}  # 🔥 แปลง key เป็น string

    # ✅ Debug Log
    print(f"🔍 DEBUG: reviewed_dict -> {reviewed_dict}")

    # ✅ ถ้าไม่มีรีวิว ให้ส่ง `{}` ไปแทน
    reviewed_json = json.dumps(reviewed_dict) if reviewed_dict else "{}"

    return render(request, 'order_history.html', {
        'orders': orders,
        'pending_orders': pending_orders,
        'completed_orders': completed_orders,
        'cancelled_orders': cancelled_orders,
        'return_orders': return_orders,
        'reviewed_products': reviewed_json,  # ✅ JSON ถูกต้อง
    })

@login_required
def refund_history(request):
    """ แสดงประวัติการคืนสินค้า """
    return_orders = RefundRequest.objects.filter(user=request.user, status="refunded")\
                                        .select_related("order", "order__seller", "item", "item__product")\
                                        .prefetch_related("order__order_items", "order__order_items__product")

    return render(request, "refund_history.html", {"return_orders": return_orders})




def order_detail(request, order_id):
    """ ดูรายละเอียดคำสั่งซื้อ """
    order = get_object_or_404(Order, id=order_id, user=request.user)
    return render(request, "order_detail.html", {"order": order})



from .models import ShippingAddress

def get_shipping_address(user):
    """ ฟังก์ชันดึงข้อมูลที่อยู่จัดส่งของผู้ใช้ """
    try:
        shipping_address = ShippingAddress.objects.get(user=user)
        return shipping_address
    except ShippingAddress.DoesNotExist:
        return None

# ✅ ฟังก์ชันสำหรับการสั่งซื้อสินค้า
@login_required
def confirm_order(request):
    """ ยืนยันคำสั่งซื้อ แยกออเดอร์ตามร้านค้า ลดสต๊อก และแนบสลิปการชำระเงิน """
    if request.method == "POST":
        # รับค่าที่อยู่จัดส่งจากฟอร์ม
        shipping_address_id = request.POST.get("shipping_address")
        shipping_address = get_object_or_404(ShippingAddress, id=shipping_address_id, user=request.user)

        # ดึงข้อมูลตะกร้าสินค้า
        cart = Cart.objects.get(user=request.user)
        cart_items = CartItem.objects.filter(cart=cart)

        if not cart_items:
            messages.error(request, "❌ ไม่มีสินค้าในตะกร้า กรุณาเลือกสินค้าก่อนทำการสั่งซื้อ!")
            return redirect("cart")

        # แยกสินค้าออกเป็นออเดอร์ตามร้านค้า
        orders_by_seller = {}
        for item in cart_items:
            seller = item.product.seller
            if seller not in orders_by_seller:
                orders_by_seller[seller] = []
            orders_by_seller[seller].append(item)

        order_ids = []  # เก็บ ID ของออเดอร์ทั้งหมดที่สร้างขึ้น

        # ✅ สร้างคำสั่งซื้อแยกตามร้านค้า
        for seller, items in orders_by_seller.items():
            total_price = sum(item.quantity * item.product.price for item in items)

            # ✅ ตรวจสอบว่าสินค้าในสต๊อกเพียงพอหรือไม่
            for item in items:
                if item.product.stock < item.quantity:
                    messages.error(request, f"❌ สินค้า {item.product.name} มีไม่พอในสต๊อก! (เหลือ {item.product.stock} ชิ้น)")
                    return redirect("cart")

            # ✅ สร้างออเดอร์
            order = Order.objects.create(
                user=request.user,
                seller=seller,
                shipping_address=shipping_address.address,
                city=shipping_address.city,  # ✅ เก็บค่าเมือง
                postal_code=shipping_address.postal_code,  # ✅ เก็บค่ารหัสไปรษณีย์
                phone_number=shipping_address.phone_number,
                total_price=total_price,
                status="pending",
                payment_status="pending",
            )

            for item in items:
                if item.product.stock < item.quantity:
                    messages.error(request, f"❌ สินค้า {item.product.name} มีไม่พอในสต๊อก! (เหลือ {item.product.stock} ชิ้น)")
                    return redirect("cart")

                OrderItem.objects.create(
                    order=order,
                    product=item.product,
                    seller=item.product.seller,
                    quantity=item.quantity,
                    price_per_item=item.product.price,
                )

                item.product.stock -= item.quantity
                item.product.save()

            # ✅ แจ้งเตือนเจ้าของร้านค้าเกี่ยวกับคำสั่งซื้อใหม่
            create_notification(user=seller.user, sender=request.user, notification_type='new_order', order=order)

            order_ids.append(order.id)

        # ✅ ลบสินค้าออกจากตะกร้า
        cart_items.delete()

        messages.success(request, "✅ คำสั่งซื้อของคุณถูกยืนยันเรียบร้อยแล้ว!")

        # ✅ นำผู้ใช้ไปยังหน้าชำระเงิน (ถ้ามีการอัปโหลดสลิป)
        return redirect("upload_payment", order_ids=",".join(map(str, order_ids)))

    return redirect("checkout")



@login_required
def edit_order(request, order_id):
    # ดึงคำสั่งซื้อที่ต้องการแก้ไข
    order = get_object_or_404(Order, id=order_id, user=request.user)
    
    # ทำการอัปเดตข้อมูลหากผู้ใช้ทำการส่งข้อมูล (POST)
    if request.method == 'POST':
        # ตัวอย่างการแก้ไขสถานะการสั่งซื้อหรือที่อยู่
        order.shipping_address.address = request.POST.get('address', order.shipping_address.address)
        order.shipping_address.phone_number = request.POST.get('phone_number', order.shipping_address.phone_number)
        order.save()
        # ส่งข้อความแจ้งเตือนและเปลี่ยนเส้นทางไปที่หน้าประวัติการสั่งซื้อ
        messages.success(request, 'คำสั่งซื้อได้รับการอัปเดตเรียบร้อยแล้ว')
        return redirect('order_history')

    return render(request, 'edit_order.html', {'order': order})

@login_required
def edit_shipping_address(request, order_id):
    order = get_object_or_404(Order, id=order_id, user=request.user)

    if request.method == "POST":
        new_address = request.POST.get("address", "").strip()  # ✅ ใช้ key name ให้ตรงกับ HTML
        new_phone = request.POST.get("phone_number", "").strip()

        # ป้องกันการเซฟค่า NULL
        if new_address and new_phone:
            order.shipping_address = new_address
            order.phone_number = new_phone
            order.save()
            return redirect("order_history")  # กลับไปหน้า order history
        else:
            error_message = "กรุณากรอกข้อมูลให้ครบถ้วน"
            return render(request, "edit_shipping_address.html", {"order": order, "error_message": error_message})

    return render(request, "edit_shipping_address.html", {"order": order})

@login_required
def seller_orders(request):
    """ แสดงคำสั่งซื้อของผู้ขาย """

    # ✅ ตรวจสอบว่า user เป็น seller
    if not hasattr(request.user, "seller_profile") or request.user.role != "seller":
        raise PermissionDenied("คุณไม่มีสิทธิ์เข้าถึงหน้านี้")

    seller = request.user.seller_profile

    # ✅ ดึงออเดอร์พร้อมสินค้าที่สั่ง
    orders = Order.objects.filter(seller=seller).prefetch_related("order_items__product").order_by("-created_at")

    return render(request, "seller_orders.html", {"orders": orders})

@login_required
def update_order_status(request, order_id, status):
    """ ✅ ผู้ขายเปลี่ยนสถานะการจัดส่ง """
    order = get_object_or_404(Order, id=order_id, seller=request.user.seller_profile)

    if status in ["processing", "shipped", "cancelled"] and order.status not in ["delivered"]:
        order.status = status
        order.save()
        messages.success(request, f"✅ อัปเดตออเดอร์ #{order.id} เป็น '{status}' แล้ว!")

    return redirect("seller_orders")

@login_required
def confirm_delivery(request, order_id):
    """ ให้ผู้ใช้กดยืนยันว่าได้รับสินค้าแล้ว """
    order = get_object_or_404(Order, id=order_id, user=request.user)

    if order.status == "shipped":
        order.status = "delivered"
        order.save()
        messages.success(request, "✅ คุณได้รับสินค้าเรียบร้อยแล้ว!")

    return redirect("order_history")



@login_required
def sellercancel_order(request, order_id):
    """ ยกเลิกคำสั่งซื้อ """
    order = get_object_or_404(Order, id=order_id, seller=request.user.seller_profile)
    order.status = "canceled"
    order.save()
    
    return redirect("seller_orders")


@login_required
def seller_payment_verification(request):
    """ ✅ แสดงคำสั่งซื้อที่รอการตรวจสอบการชำระเงินสำหรับผู้ขาย """

    # ✅ ป้องกัน user ที่ไม่ใช่ seller
    if not hasattr(request.user, 'seller_profile') or request.user.role != 'seller':
        raise PermissionDenied("คุณไม่มีสิทธิ์เข้าถึงหน้านี้")

    orders = Order.objects.filter(
        seller=request.user.seller_profile,
        payment_status="pending"
    ).exclude(status="cancelled")

    return render(request, "seller_payment_verification.html", {
        "orders": orders
    })


def reject_seller_payment(request, order_id):
    order = get_object_or_404(Order, id=order_id)
    
    if order.payment_status == "pending":
        order.payment_status = "rejected"
        order.save()

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({"success": True, "message": f"ออเดอร์ #{order.id} ถูกปฏิเสธแล้ว!"})
        
        return redirect('seller_payment_verification')  # ✅ Redirect กลับไปยังหน้าเดิม


@login_required
def follow_user(request, user_id):
    """ ✅ ติดตามหรือเลิกติดตามผู้ใช้ """
    if request.method != "POST":
        return JsonResponse({"success": False, "message": "Invalid request method"}, status=400)

    target_user = get_object_or_404(CustomUser, id=user_id)

    if request.user == target_user:
        return JsonResponse({"success": False, "message": "คุณไม่สามารถติดตามตัวเองได้"}, status=400)

    follow_instance, created = Follow.objects.get_or_create(follower=request.user, following=target_user)

    if not created:
        follow_instance.delete()
        is_following = False
    else:
        is_following = True

    followers_count = Follow.objects.filter(following=target_user).count()
    following_count = Follow.objects.filter(follower=request.user).count()

    return JsonResponse({
        "success": True,
        "is_following": is_following,
        "followers_count": followers_count,
        "following_count": following_count
    })

@login_required
def follow_status(request, user_id):
    """ ✅ ตรวจสอบว่ายูสเซอร์ที่ล็อกอินติดตาม user_id หรือไม่ """
    target_user = get_object_or_404(CustomUser, id=user_id)
    is_following = Follow.objects.filter(follower=request.user, following=target_user).exists()

    return JsonResponse({"success": True, "is_following": is_following})

@login_required
def delete_uploaded_file(request, file_id):
    media = get_object_or_404(PostMedia, id=file_id)
    
    # ตรวจสอบว่าเป็นไฟล์ของโพสต์ที่ผู้ใช้เป็นเจ้าของ
    if media.post.user != request.user:
        return JsonResponse({"success": False, "message": "Unauthorized"}, status=403)

    media.delete()
    return JsonResponse({"success": True, "message": "File deleted"}, status=200)

from django.shortcuts import render, get_object_or_404
from .models import GroupPost

def group_post_detail(request, post_id):
    post = get_object_or_404(GroupPost, id=post_id)
    return render(request, 'group_post_detail.html', {'post': post})

#รายละเอียดกลุ่มใน noti
# @login_required
# def edit_group_post(request, post_id):
#     post = get_object_or_404(GroupPost, id=post_id, user=request.user)

#     if request.method == "POST":
#         content = request.POST.get("content", "").strip()
#         images = request.FILES.getlist("images")
#         videos = request.FILES.getlist("videos")

#         # ✅ อัปเดตเนื้อหาโพสต์
#         post.content = content
#         post.save()

#         # ✅ ลบไฟล์ที่ผู้ใช้เลือก
#         delete_media_ids = request.POST.getlist("delete_media")
#         GroupPostMedia.objects.filter(id__in=delete_media_ids, post=post).delete()

#         # ✅ เพิ่มไฟล์ใหม่
#         for image in images:
#             GroupPostMedia.objects.create(post=post, file=image, media_type="image")

#         for video in videos:
#             GroupPostMedia.objects.create(post=post, file=video, media_type="video")

#         return redirect('group_post_detail', post_id=post.id)



# ✅ ลบคอมเมนต์ (รองรับ JSON request)
@login_required
def delete_comment(request, comment_id):
    try:
        comment_id = int(comment_id)
    except ValueError:
        return JsonResponse({"success": False, "message": "Invalid comment ID!"}, status=400)

    comment = get_object_or_404(Comment, id=comment_id, user=request.user)

    if request.method == "POST":
        comment.delete()
        return JsonResponse({"success": True, "message": "คอมเมนต์ถูกลบเรียบร้อยแล้ว"}, status=200)

    return JsonResponse({"success": False, "message": "Invalid request"}, status=400)


# ✅ แก้ไขคอมเมนต์ (รองรับ JSON request)
@login_required
def edit_comment(request, comment_id):
    try:
        comment_id = int(comment_id)
    except ValueError:
        return JsonResponse({"success": False, "message": "Invalid comment ID!"}, status=400)

    comment = get_object_or_404(Comment, id=comment_id, user=request.user)

    if request.method == "POST":
        # เช็คว่าเป็น JSON หรือ FormData
        if request.content_type == "application/json":
            try:
                data = json.loads(request.body)
                content = data.get("content", "").strip()
            except json.JSONDecodeError:
                return JsonResponse({"success": False, "message": "Invalid JSON format!"}, status=400)
        else:
            content = request.POST.get("content", "").strip()

        if content:
            comment.content = content
            comment.save()
            return JsonResponse({"success": True, "message": "Comment updated!", "content": comment.content})
        return JsonResponse({"success": False, "message": "Comment cannot be empty!"}, status=400)

    return JsonResponse({"success": False, "message": "Invalid request!"}, status=400)

def group_post_detail(request, post_id):
    post = get_object_or_404(GroupPost, id=post_id)
    return render(request, 'group_post_detail.html', {'post': post})









@login_required
def approve_seller_payment(request, order_id):
    """ ✅ อนุมัติการชำระเงิน และอัปเดตยอดเงินของผู้ขาย """
    order = get_object_or_404(Order, id=order_id, seller=request.user.seller_profile)

    if not hasattr(order, 'payment'):
        messages.error(request, "❌ ไม่พบหลักฐานการชำระเงิน")
        return redirect('seller_orders')  # 🔄 เปลี่ยนเส้นทางไปหน้าจัดการคำสั่งซื้อของผู้ขาย

    # ✅ เปลี่ยนสถานะเป็น "paid" และ "processing"
    order.payment_status = "paid"
    order.status = "processing"
    order.save()

    # ✅ อัปเดตกระเป๋าเงินของผู้ขาย
    seller_wallet, created = SellerWallet.objects.get_or_create(seller=order.seller)

    # 🔥 แปลง balance เป็น Decimal ก่อนบวก
    seller_wallet.balance = Decimal(seller_wallet.balance) + order.total_price
    seller_wallet.save()

    messages.success(request, f"✅ ออเดอร์ #{order.id} อนุมัติแล้ว และเครดิตเงินเข้ากระเป๋า!")
    
    return redirect('seller_payment_verification')  # 🔄 เปลี่ยนเส้นทางกลับไปที่หน้า seller_orders


@login_required
def report_post(request, post_id):
    post = get_object_or_404(Post, id=post_id)
    
    # ป้องกันไม่ให้ผู้ใช้รีพอร์ตโพสต์ของตัวเอง
    if post.user == request.user:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'success': False, 'message': 'คุณไม่สามารถรีพอร์ตโพสต์ของตัวเองได้!'})
        messages.error(request, "❌ คุณไม่สามารถรีพอร์ตโพสต์ของตัวเองได้!")
        return redirect('home')
    
    if request.method == 'POST':
        form = ReportForm(request.POST)
        if form.is_valid():
            # สร้างรายงาน
            report = Report.objects.create(
                post=post,
                reported_by=request.user,
                reason=form.cleaned_data['reason'],
                description=form.cleaned_data['description']
            )
            
            # เก็บ report id ไว้ใน session
            request.session['report_id'] = report.id
            
            # ตอบกลับเป็น JSON ถ้าเป็น AJAX request
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                    'success': True, 
                    'message': 'ส่งรายงานโพสต์เรียบร้อยแล้ว',
                    'report_id': report.id
                })
            
            messages.success(request, "ส่งรายงานโพสต์เรียบร้อยแล้ว")
            return redirect('block_user', post.user.id)
    else:
        form = ReportForm()
    
    return render(request, 'report_post.html', {'form': form, 'post': post})


@login_required
def block_user(request, user_id):
    blocked_user = get_object_or_404(User, id=user_id)
    
    if blocked_user == request.user:
        messages.error(request, "❌ คุณไม่สามารถบล็อกตัวเองได้!")
        return redirect('home')
    
    # ดึงข้อมูลรายงานจาก session หรือจาก POST data
    report_id = request.POST.get('report_id') or request.session.get('report_id')
    report = None
    
    if report_id:
        report = get_object_or_404(Report, id=report_id)
    
    if request.method == 'POST':
        action = request.POST.get('action', '')
        
        if action == 'block':
            # สร้างการบล็อคผู้ใช้
            BlockedUser.objects.create(blocked_by=request.user, blocked_user=blocked_user)
            
            # ถ้ามีรายงาน ให้ซ่อนโพสต์ด้วย
            if report:
                post = report.post
                post.is_reported = True
                post.save()
            
            messages.success(request, f"✅ คุณได้บล็อก {blocked_user.username} แล้ว")
        else:  # action == 'cancel'
            messages.info(request, f"คุณไม่ได้บล็อก {blocked_user.username}")
        
        # ลบข้อมูลรายงานออกจาก session
        if 'report_id' in request.session:
            del request.session['report_id']
        
        return redirect('home')
    
    # กรณีเข้าถึงหน้า block_user โดยตรง (ไม่ผ่าน AJAX)
    return render(request, 'block_user.html', {'blocked_user': blocked_user, 'report': report})

@login_required
def blocked_users_list(request):
    # ดึงรายการผู้ใช้ที่ถูกบล็อค
    blocked_users = BlockedUser.objects.filter(blocked_by=request.user).order_by('-created_at')
    
    context = {
        'blocked_users': blocked_users,
        # 'products': products,
    }
    
    return render(request, 'blocked_users_list.html', context)

@login_required
def unblock_user(request, user_id):
    # ดึงข้อมูลผู้ใช้ที่ถูกบล็อค
    blocked_user = get_object_or_404(User, id=user_id)
    
    # ตรวจสอบว่าผู้ใช้นี้ถูกบล็อคจริงหรือไม่
    blocked = BlockedUser.objects.filter(blocked_by=request.user, blocked_user=blocked_user).first()

    
    if not blocked:
        messages.error(request, 'ผู้ใช้นี้ไม่ได้ถูกบล็อค')
        return redirect('blocked_users_list')
    
    # ถ้าส่งฟอร์มมา
    if request.method == 'POST':
        # ลบข้อมูลการบล็อคจากตาราง
        blocked.delete()
        
        messages.success(request, f'คุณได้เลิกบล็อค {blocked_user.username} เรียบร้อยแล้ว')
        return redirect('blocked_users_list')
    
    # แสดงหน้ายืนยันการเลิกบล็อค
    return render(request, 'unblock_user.html', {'blocked_user': blocked_user})


# #แสดงการบล็อคผู้ใช้
# from.models import BlockedUser
# @login_required
# def block_user(request, user_id):
#     blocked_user = get_object_or_404(User, id=user_id)

#     if blocked_user == request.user:
#         messages.error(request, "❌ คุณไม่สามารถบล็อกตัวเองได้!")
#         return redirect('home')

#     if request.method == 'POST':
#         BlockedUser.objects.create(blocked_by=request.user, blocked_user=blocked_user)
#         messages.success(request, f"✅ คุณได้บล็อก {blocked_user.username} แล้ว")
#         return redirect('home')

#     return render(request, 'block_user.html', {'blocked_user': blocked_user})

# ตรวจสอบว่าเป็นแอดมินหรือไม่
def is_admin(user):
    return user.is_authenticated and user.is_staff

# แอดมินล็อกอิน
def admin_login(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)  # ตรวจสอบข้อมูล

        if user is not None and user.is_staff:  # เช็คว่าเป็นแอดมิน
            login(request, user)  # ทำการ Login
            return redirect("admin_dashboard")  # ไปที่หน้าหลักของแอดมิน
        else:
            messages.error(request, "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง หรือคุณไม่มีสิทธิ์เข้าถึงแอดมิน")  # แสดง Error

    return render(request, "admin_login.html")


def admin_register(request):
    if request.method == 'POST':
        form = AdminRegisterForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Admin account created successfully. You can now log in.")
            return redirect('admin_login')  # ✅ หลังสมัครเสร็จให้ไปหน้า login
    else:
        form = AdminRegisterForm()

    return render(request, 'admin_register.html', {'form': form})

def is_admin(user):
    return user.is_superuser

# แสดงแดชบอร์ดแอดมิน
# แสดงแดชบอร์ดแอดมิน (เฉพาะแอดมินเข้าได้)
@login_required(login_url="/admin_login/")
def admin_dashboard(request):
    # Get reported posts
    reported_posts = Report.objects.select_related('post', 'reported_by').order_by('-created_at')
    
    # Get total users
    total_users = User.objects.count()
    
    # Get total shops/sellers
    total_shops = Seller.objects.count()
    
    # Get orders created today
    from django.utils import timezone
    today = timezone.now().date()
    orders_today = Order.objects.filter(created_at__date=today).count()
    
    context = {
        "reported_posts": reported_posts,
        "total_users": total_users,
        "total_shops": total_shops,
        "orders_today": orders_today
    }
    
    return render(request, "admin_dashboard.html", context)

# ลบโพสต์ที่ถูกรีพอร์ต
@user_passes_test(is_admin)
def delete_reported_post(request, post_id):
    post = Post.objects.filter(id=post_id).first()
    if post:
        post.delete()
        messages.success(request, "Post has been deleted.")
    return redirect("admin_dashboard")

# from django.views.decorators.http import require_POST
# @require_POST
# @user_passes_test(is_admin)
# @login_required(login_url='admin_login') 
def cancel_reported_post(request, post_id):
    if not request.user.is_staff:
        messages.error(request, "คุณไม่มีสิทธิ์ในการเข้าถึง")
        return redirect("home")  # หรือหน้าที่คุณอยากส่งกลับเมื่อไม่ใช่แอดมิน

    post = Post.objects.filter(id=post_id).first()
    reports = Report.objects.filter(post=post)
    
    if post:
        post.is_reported = False
        post.save()
        reports.delete()
        messages.success(request, "คำร้องรายงานโพสต์ถูกยกเลิกแล้ว")
    
    return redirect("admin_dashboard")

from django.contrib.auth.views import PasswordResetView
from django.urls import reverse_lazy

class CustomPasswordResetView(PasswordResetView):
    template_name = 'password_reset.html'  # ฟอร์มขอรหัสผ่านใหม่
    email_template_name = 'password_reset_email.html'  # เทมเพลตรูปแบบอีเมล
    subject_template_name = 'password_reset_subject.txt'  # หัวข้ออีเมล
    success_url = reverse_lazy('password_reset_done')  # หลังส่งอีเมลเสร็จให้ไปหน้านี้

# @login_required
# def get_group_posts(request, group_id):
#     group = get_object_or_404(CommunityGroup, id=group_id)
#     posts = GroupPost.objects.filter(group=group).order_by('-created_at')

#     post_list = []
#     for post in posts:
#         post_list.append({
#             'id': post.id,
#             'username': post.user.username,
#             'profile_picture': post.user.member_profile.profile_picture.url if post.user.member_profile.profile_picture else None,
#             'content': post.content,
#             'created_at': post.created_at.strftime('%b %d, %Y %H:%M'),
#             'image_url': post.image.url if post.image else None,
#             'video_url': post.video.url if post.video else None,
#             'is_owner': request.user == post.user  # ✅ ตรวจสอบว่าผู้ใช้เป็นเจ้าของโพสต์หรือไม่
#         })

#     return JsonResponse({'posts': post_list}, status=200)


@login_required
def manage_addresses(request):
    """ แสดงที่อยู่ทั้งหมดของผู้ใช้ """
    saved_addresses = ShippingAddress.objects.filter(user=request.user)
    return render(request, "manage_addresses.html", {"saved_addresses": saved_addresses})

@login_required
def add_address(request):
    """ เพิ่มที่อยู่จัดส่งใหม่ """
    if request.method == "POST":
        form = ShippingAddressForm(request.POST)
        if form.is_valid():
            new_address = form.save(commit=False)
            new_address.user = request.user
            new_address.save()
            messages.success(request, "✅ เพิ่มที่อยู่สำเร็จ!")
            return redirect('manage_addresses')
    else:
        form = ShippingAddressForm()

    return render(request, 'add_address.html', {'form': form})

@login_required
def edit_address(request, address_id):
    """ แก้ไขที่อยู่จัดส่ง """
    address = get_object_or_404(ShippingAddress, id=address_id, user=request.user)

    if request.method == "POST":
        form = ShippingAddressForm(request.POST, instance=address)
        if form.is_valid():
            form.save()
            messages.success(request, "✅ แก้ไขที่อยู่สำเร็จ!")
            return redirect('manage_addresses')

    else:
        form = ShippingAddressForm(instance=address)

    return render(request, 'edit_address.html', {'form': form})

@login_required
def delete_address(request, address_id):
    """ ลบที่อยู่จัดส่ง """
    address = get_object_or_404(ShippingAddress, id=address_id, user=request.user)
    address.delete()
    messages.success(request, "🗑 ลบที่อยู่สำเร็จ!")
    return redirect('manage_addresses')




from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.db.models import Sum, F
from .models import SellerWallet, WithdrawalRequest, RefundRequest, OrderItem, Order

from decimal import Decimal
from django.db.models import Sum, Q
@login_required
def seller_wallet(request):
    seller = request.user.seller_profile
    wallet, created = SellerWallet.objects.get_or_create(seller=seller)
    withdrawals = WithdrawalRequest.objects.filter(seller=seller).order_by('-created_at')

    # ✅ คำนวณรายได้ที่ถอนได้:
    withdrawable_orders = Order.objects.filter(
        seller=seller,
        payment_status="paid"
    ).exclude(
        status="packing"  # ❌ ไม่รวมออเดอร์ที่ยังอยู่ระหว่างแพ็ค
    )

    withdrawable_income = withdrawable_orders.aggregate(
        total=Sum("total_price")
    )["total"] or Decimal("0.00")

    return render(request, 'seller_wallet.html', {
        'wallet': wallet,
        'withdrawals': withdrawals,
        'withdrawable_income': withdrawable_income,
    })

from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Order, OrderItem

@receiver(post_save, sender=Order)
def update_product_sales(sender, instance, **kwargs):
    """ ✅ อัปเดตจำนวนสินค้าที่ขายได้เมื่อคำสั่งซื้อถูกส่งสำเร็จ """
    if instance.status == "delivered":  # ตรวจสอบว่าจัดส่งแล้ว
        for item in instance.order_items.all():
            item.product.total_sold += item.quantity
            item.product.save()

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import Order, RefundRequest
from .forms import RefundRequestForm

@login_required
def request_refund(request, order_id):
    """ ฟังก์ชันให้ผู้ใช้ขอคืนเงินสำหรับทั้งออเดอร์ (รวมถึงกรณียกเลิกแล้วแต่ชำระเงินแล้ว) """
    order = get_object_or_404(Order, id=order_id, user=request.user)
    order_items = order.order_items.all()

    # ✅ ตรวจสอบว่ามีคำขอคืนเงินไปแล้วหรือยัง
    if RefundRequest.objects.filter(order=order).exists():
        messages.warning(request, "⚠️ คุณได้ส่งคำขอคืนเงินสำหรับออเดอร์นี้ไปแล้ว")
        return redirect("order_history")

    # ✅ ต้องเป็นออเดอร์ที่ "ชำระเงินแล้ว"
    if order.payment_status != "paid":
        messages.error(request, "⛔ ไม่สามารถขอคืนเงินได้ เนื่องจากยังไม่ได้ชำระเงิน")
        return redirect("order_history")

    if request.method == "POST":
        return_item_proof = request.FILES.get("return_item_proof")

        refund_request = RefundRequest.objects.create(
            user=request.user,
            order=order,
            account_name=request.POST.get("account_name"),
            account_number=request.POST.get("account_number"),
            bank_name=request.POST.get("bank_name"),
            refund_reason=request.POST.get("refund_reason"),
            payment_proof=request.FILES.get("payment_proof"),
            return_item_proof=return_item_proof,
            status="pending",
        )

        # ✅ เปลี่ยนสถานะออเดอร์เป็น refunded (ขอคืนเงิน)
        order.status = "refunded"
        order.save()

        messages.success(request, "✅ ส่งคำขอคืนเงินสำเร็จ 🎉")
        return redirect("order_history")

    return render(request, "partials/refund_request.html", {
        "order": order,
        "order_items": order_items,
    })


@login_required
def seller_refund_requests(request):
    """ แสดงรายการคำขอคืนเงินของผู้ขาย """

    # ✅ ตรวจสอบว่าเป็นผู้ขายเท่านั้น
    if not hasattr(request.user, 'seller_profile') or request.user.role != 'seller':
        raise PermissionDenied("คุณไม่มีสิทธิ์เข้าถึงหน้านี้")

    seller = request.user.seller_profile

    refund_requests = RefundRequest.objects.filter(order__seller=seller)\
                                           .select_related("order", "user", "item", "item__product")\
                                           .prefetch_related("order__order_items", "order__order_items__product")

    return render(request, "refund_requests_seller.html", {
        "refund_requests": refund_requests
    })




from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.contrib.auth.decorators import login_required
from myapp.models import RefundRequest
from myapp.forms import RefundProofForm

@login_required
def upload_refund_proof(request, refund_id):
    """ ผู้ขายอัปโหลดหลักฐานการคืนเงิน """
    refund_request = get_object_or_404(RefundRequest, id=refund_id, order__seller=request.user.seller_profile)

    if request.method == "POST":
        form = RefundProofForm(request.POST, request.FILES, instance=refund_request)
        if form.is_valid():
            refund_request.status = "refunded"  # ✅ อัปเดตสถานะเป็นคืนเงินแล้ว
            form.save()

            # ✅ แจ้งเตือนลูกค้าว่าผู้ขายได้อัปโหลดสลิปคืนเงินแล้ว
            Notification.objects.create(
                user=refund_request.user,
                sender=request.user,
                notification_type="refund_completed",
                order=refund_request.order,
            )

            messages.success(request, "✅ อัปโหลดสลิปคืนเงินสำเร็จ! รอลูกค้ายืนยัน")
            return redirect("seller_refund_requests")
    
    else:
        form = RefundProofForm(instance=refund_request)

    return render(request, "refund_upload.html", {
        "refund_request": refund_request,
        "form": form
    })



@login_required
def approve_refund(request, refund_id):
    """ ผู้ขายอนุมัติคำขอคืนเงิน """
    refund_request = get_object_or_404(RefundRequest, id=refund_id, order__seller=request.user.seller_profile)

    if refund_request.status == "pending":
        refund_request.status = "approved"
        refund_request.save()

        # ✅ สร้าง Notification ให้ลูกค้าทราบว่าได้รับการอนุมัติ
        Notification.objects.create(
            user=refund_request.user,
            sender=request.user,
            notification_type="refund_approved",
            order=refund_request.order,
        )

        messages.success(request, "✅ อนุมัติคำขอคืนเงินสำเร็จ! กรุณาอัปโหลดสลิปการโอนคืนเงิน")
    
    return redirect("seller_refund_requests")


@login_required
def reject_refund(request, refund_id):
    """ ปฏิเสธคำขอคืนเงิน """
    refund_request = get_object_or_404(RefundRequest, id=refund_id, order__seller=request.user.seller_profile)

    # ❌ เปลี่ยนสถานะเป็น "rejected"
    refund_request.status = "rejected"
    refund_request.save()

    messages.error(request, f"❌ ปฏิเสธคำขอคืนเงินสำหรับคำขอ #{refund_request.id} เรียบร้อย")
    return redirect("seller_refund_requests")

@login_required
def confirm_refund_received(request, refund_id):
    """ ลูกค้ายืนยันว่าได้รับเงินคืนแล้ว """
    refund_request = get_object_or_404(RefundRequest, id=refund_id, user=request.user)

    if refund_request.status == "refunded":
        refund_request.status = "confirmed"
        refund_request.confirmed_by_user = True
        refund_request.save()

        # ✅ แจ้งเตือนผู้ขายว่าลูกค้าได้รับเงินคืนแล้ว
        Notification.objects.create(
            user=refund_request.order.seller.user,  # ผู้ขาย
            sender=request.user,
            notification_type="refund_confirmed",
            order=refund_request.order,
        )

        messages.success(request, "✅ คุณได้ยืนยันว่าได้รับเงินคืนแล้ว")
    
    return redirect("order_history")


from .models import SellerWallet, WithdrawalRequest
from .forms import WithdrawalForm

from django.shortcuts import redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Sum, F
from .models import SellerWallet, WithdrawalRequest, OrderItem, RefundRequest

@login_required
def request_withdrawal(request):
    if request.method == "POST":
        seller = request.user.seller_profile  # ดึงข้อมูลผู้ขาย
        wallet = seller.wallet
        
        if wallet.balance <= 0:
            messages.error(request, "❌ ยอดเงินไม่พอสำหรับการถอน")
            return redirect("seller_wallet")

        # บันทึกคำขอถอนเงิน
        WithdrawalRequest.objects.create(
            seller=seller,
            amount=wallet.balance,
            status="pending"
        )

        # รีเซ็ตยอดเงินให้เป็น 0
        wallet.balance = 0
        wallet.save()

        messages.success(request, "✅ คำขอถอนเงินถูกส่งไปยังแอดมินแล้ว")
        return redirect("seller_wallet")
    
    return redirect("seller_wallet")


from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import user_passes_test
from django.contrib import messages
from .models import WithdrawalRequest
from .models import WithdrawalRequest
from .forms import WithdrawalProofForm

from django.contrib.auth.decorators import user_passes_test

def is_admin(user):
    return user.is_authenticated and user.is_staff  # ✅ เฉพาะแอดมิน

@login_required(login_url="/admin_login/")
def admin_withdrawals(request):
    if not request.user.is_staff:  # ✅ ถ้าไม่ใช่แอดมิน รีไดเรกต์ไปหน้าอื่น
        return redirect('home')

    withdrawals = WithdrawalRequest.objects.all().order_by("-created_at")
    return render(request, "admin_withdrawals.html", {"withdrawals": withdrawals})


from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import user_passes_test, login_required
from django.contrib import messages
from .models import WithdrawalRequest

@user_passes_test(lambda u: u.is_staff)  # ✅ ให้เฉพาะแอดมินเข้าถึง
def approve_withdrawal(request, withdrawal_id):
    withdrawal = get_object_or_404(WithdrawalRequest, id=withdrawal_id)
    
    if request.method == "POST" and request.FILES.get("payment_proof"):
        withdrawal.status = "approved"
        withdrawal.payment_proof = request.FILES["payment_proof"]
        withdrawal.save()
        messages.success(request, "✅ อนุมัติคำขอถอนเงินเรียบร้อย")

    return redirect("admin_withdrawals")

@user_passes_test(lambda u: u.is_staff)
def reject_withdrawal(request, withdrawal_id):
    withdrawal = get_object_or_404(WithdrawalRequest, id=withdrawal_id)
    
    if request.method == "POST":
        withdrawal.status = "rejected"
        withdrawal.save()
        messages.error(request, "❌ ปฏิเสธคำขอถอนเงินเรียบร้อย")

    return redirect("admin_withdrawals")

@login_required
def confirm_withdrawal(request, withdrawal_id):
    withdrawal = get_object_or_404(WithdrawalRequest, id=withdrawal_id, seller=request.user.seller_profile)
    
    if request.method == "POST":
        withdrawal.confirmed_by_seller = True
        withdrawal.save()
        messages.success(request, "✅ ยืนยันการรับเงินสำเร็จ")

    return redirect("seller_wallet")


from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.db.models import Sum, Avg, Count
from .models import Order, Product, Review, RefundRequest

@login_required
def seller_performance(request):
    seller = request.user.seller_profile

    # ✅ ยอดขายรวม
    completed_orders = Order.objects.filter(seller=seller, status="delivered").exclude(refund_requests__status="approved")
    total_sales = completed_orders.aggregate(Sum("total_price"))["total_price__sum"] or 0

    # ✅ สินค้าขายดี (5 อันดับแรกสำหรับตาราง)
    sold_products = (
        OrderItem.objects.filter(order__seller=seller)
        .exclude(refund_requests__status="approved")
        .values("product__id", "product__name")
        .annotate(total_sold_count=Sum("quantity"))
        .order_by("-total_sold_count")[:5]
    )
    top_products = []
    for item in sold_products:
        product = Product.objects.get(id=item["product__id"])
        product.total_sold_count = item["total_sold_count"]
        top_products.append(product)

    # ✅ Top 10 สำหรับกราฟ
    top10_data = (
        OrderItem.objects.filter(order__seller=seller)
        .exclude(refund_requests__status="approved")
        .values("product__name")
        .annotate(total_sold=Sum("quantity"))
        .order_by("-total_sold")[:10]
    )
    top10_names = [item["product__name"] for item in top10_data]
    top10_counts = [int(item["total_sold"]) for item in top10_data]

    # ✅ ยอดขายรายเดือน
    monthly_sales_data = (
        Order.objects.filter(seller=seller, payment_status='paid')
        .annotate(month=TruncMonth("created_at"))
        .values("month")
        .annotate(total=Sum("total_price"))
        .order_by("month")
    )
    monthly_labels = [entry["month"].strftime("%b %Y") for entry in monthly_sales_data]
    monthly_sales = [float(entry["total"]) for entry in monthly_sales_data]

    # ✅ คะแนนรีวิว
    reviews = Review.objects.filter(product__seller=seller)
    avg_rating = reviews.aggregate(Avg("rating"))["rating__avg"] or 0
    review_distribution = [
        reviews.filter(rating=5).count(),
        reviews.filter(rating=4).count(),
        reviews.filter(rating=3).count(),
        reviews.filter(rating=2).count(),
        reviews.filter(rating=1).count(),
    ]
    recent_reviews = reviews.order_by("-created_at")[:5]

    # ✅ การคืนสินค้า
    refunds = RefundRequest.objects.filter(order__seller=seller, status="approved").count()

    return render(request, "seller_performance.html", {
        "total_sales": total_sales,
        "top_products": top_products,
        "refunds": refunds,
        "avg_rating": avg_rating,
        "recent_reviews": recent_reviews,
        "top10_names": json.dumps(top10_names),
        "top10_counts": json.dumps(top10_counts),
        "monthly_labels": json.dumps(monthly_labels),
        "monthly_sales": json.dumps(monthly_sales),
        "review_distribution": json.dumps(review_distribution),
    })

def is_admin(user):
    return user.is_staff  # ✅ อนุญาตเฉพาะแอดมิน

#แสดงกราฟหน้าแอดมิน
from django.db.models import Sum, Count, F, Q, Case, When, Value, ExpressionWrapper, FloatField, Subquery, OuterRef
# from django.db.models.functions import TruncDate
from django.db.models.functions import TruncMonth, TruncDate
@user_passes_test(is_admin)
def admin_performance(request):
    """ แสดงรายงานสถิติของผู้ขายทั้งหมด """

    # ยอดขายรวมทั้งหมด
    total_sales = Order.objects.filter(status="delivered").aggregate(Sum("total_price"))["total_price__sum"] or 0

    # ยอดขายรายเดือน
    sales_by_month = (
        Order.objects.filter(status="delivered", created_at__isnull=False)
        .annotate(month=TruncMonth("created_at"))
        .values("month")
        .annotate(total_sales=Sum("total_price"))
        .order_by("month")
    )

    # ผู้ขายที่มียอดขายสูงสุด
    top_sellers = (
        Seller.objects.annotate(
            total_revenue=Sum("orders__total_price"),
            order_count=Count("orders"),
            refund_rate=ExpressionWrapper(
                Count("orders__refund_requests", filter=Q(orders__refund_requests__status="approved")) * 100.0 / 
                Case(When(order_count=0, then=Value(1)), default="order_count", output_field=FloatField()),
                output_field=FloatField()
            )
        )
        .order_by("-total_revenue")[:10]
    )

    # การคืนสินค้ารายเดือน
    refunds_by_month = (
        RefundRequest.objects.values("created_at__year", "created_at__month")
        .annotate(
            total_refunds=Count("id"),
            refund_rate=ExpressionWrapper(
                F("total_refunds") * 100.0 / 
                Case(
                    When(total_refunds=0, then=Value(1)),
                    default=Subquery(
                        Order.objects.filter(
                            created_at__year=OuterRef("created_at__year"),
                            created_at__month=OuterRef("created_at__month")
                        ).values("created_at__month").annotate(count=Count("id")).values("count")[:1]
                    ),
                    output_field=FloatField()
                ),
                output_field=FloatField()
            )
        )
        .order_by("created_at__year", "created_at__month")
    )
    
    # จำนวนผู้ขายทั้งหมด (แทนที่การกรอง is_active)
    active_sellers = Seller.objects.count()
    
    # จำนวนผู้ใช้งานระบบรายวัน
    daily_users = (
        CustomUser.objects.filter(last_login__isnull=False)
        .annotate(date=TruncDate("last_login"))
        .values("date")
        .annotate(user_count=Count("id", distinct=True))
        .order_by("-date")[:30]  # แสดง 30 วันล่าสุด
    )
    
    # จำนวนสินค้าทั้งหมด
    total_products = Product.objects.count()
    
    # อัตราการคืนสินค้าโดยรวม
    total_orders = Order.objects.filter(status="delivered").count()
    total_refunds = RefundRequest.objects.filter(status="approved").count()
    refund_rate = (total_refunds / total_orders * 100) if total_orders > 0 else 0

    context = {
        "total_sales": total_sales,
        "sales_by_month": list(sales_by_month),
        "top_sellers": top_sellers,
        "refunds_by_month": list(refunds_by_month),
        "daily_users": list(daily_users),
        "active_sellers": active_sellers,
        "total_products": total_products,
        "refund_rate": round(refund_rate, 2)
    }

    return render(request, "admin_performance.html", context)


# กราฟแอดมิน
@user_passes_test(is_admin)
def admin_performance_chart_data(request):
    from django.db.models.functions import TruncMonth
    from django.db.models import Sum
    from myapp.models import Order, CustomUser
    from django.db.models.functions import TruncDate
    from django.http import JsonResponse

    sales_by_month = (
        Order.objects.filter(status="delivered", created_at__isnull=False)
        .annotate(month=TruncMonth("created_at"))
        .values("month")
        .annotate(total_sales=Sum("total_price"))
        .order_by("month")
    )

    daily_users = (
        CustomUser.objects.filter(last_login__isnull=False)
        .annotate(date=TruncDate("last_login"))
        .values("date")
        .annotate(user_count=Count("id"))
        .order_by("date")
    )

    sales_data = {
        'labels': [item['month'].strftime('%m/%Y') for item in sales_by_month if item['month']],
        'values': [float(item['total_sales']) for item in sales_by_month]
    }

    users_data = {
        'labels': [item['date'].strftime('%d/%m/%Y') for item in daily_users if item['date']],
        'values': [item['user_count'] for item in daily_users]
    }

    return JsonResponse({
        'sales_data': sales_data,
        'users_data': users_data
    })


from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from .models import Post, Comment

def get_comments(request, post_id):
    post = get_object_or_404(Post, id=post_id)
    comments = post.comments.all().order_by("-created_at")  # เรียงตามเวลาล่าสุด

    comment_list = [
        {
            "id": comment.id,
            "username": comment.user.username,
            "content": comment.content,
            "is_owner": comment.user == request.user,  # เช็คว่าเป็นเจ้าของคอมเมนต์หรือไม่
        }
        for comment in comments
    ]

    return JsonResponse({"comments": comment_list}, safe=False)
@login_required
def update_order_shipping(request, order_id):
    """ อัปเดตที่อยู่จัดส่งของ Order """
    order = get_object_or_404(Order, id=order_id, user=request.user)

    if request.method == "POST":
        new_address = request.POST.get("address", "").strip()
        new_city = request.POST.get("city", "").strip()
        new_postal_code = request.POST.get("postal_code", "").strip()
        new_phone = request.POST.get("phone_number", "").strip()

        # ✅ ตรวจสอบข้อมูลก่อนอัปเดต
        if new_address and new_city and new_postal_code and new_phone:
            order.shipping_address = new_address
            order.city = new_city
            order.postal_code = new_postal_code
            order.phone_number = new_phone
            order.save()  # ✅ บันทึกลงฐานข้อมูล

            return JsonResponse({
                "success": True,
                "new_address": new_address,
                "new_city": new_city,
                "new_postal_code": new_postal_code,
                "new_phone": new_phone
            })

        return JsonResponse({"success": False, "error": "กรุณากรอกข้อมูลให้ครบถ้วน"})

    return JsonResponse({"success": False, "error": "Invalid request method"}, status=400)

from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from .models import SellerNotification

@login_required
def get_seller_notifications(request):
    """ ดึงการแจ้งเตือนของผู้ขาย """
    notifications = SellerNotification.objects.filter(seller=request.user, is_read=False).order_by('-created_at')
    data = [
        {"id": n.id, "message": n.message, "created_at": n.created_at.strftime("%Y-%m-%d %H:%M"), "is_read": n.is_read}
        for n in notifications
    ]
    return JsonResponse({"notifications": data})

@csrf_exempt
@login_required
def mark_notifications_read(request):
    """ ทำเครื่องหมายแจ้งเตือนทั้งหมดว่าอ่านแล้ว (AJAX) """
    if request.method == "POST":
        SellerNotification.objects.filter(seller=request.user, is_read=False).update(is_read=True)
        return JsonResponse({"success": True})
    return JsonResponse({"error": "Invalid request method"}, status=400)

from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from .models import SellerNotification

@login_required
def seller_notifications_list(request):
    """ แสดงหน้าแจ้งเตือนทั้งหมดของผู้ขาย """
    notifications = SellerNotification.objects.filter(seller=request.user).order_by('-created_at')
    return render(request, "sellers_notifications.html", {"notifications": notifications})

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from .models import Review, ReviewResponse, Seller
from django.contrib import messages

@login_required
def seller_review_responses(request):
    """ แสดงรายการรีวิวที่ลูกค้าทิ้งไว้ให้สินค้าของผู้ขาย """
    seller = request.user.seller_profile  # ดึงข้อมูลผู้ขายจากโปรไฟล์
    reviews = Review.objects.filter(product__seller=seller)  # รีวิวที่เกี่ยวข้องกับสินค้าของผู้ขาย
    return render(request, "seller/review_responses.html", {"reviews": reviews})

@login_required
def seller_respond_review(request, review_id):
    """ ให้ผู้ขายตอบกลับรีวิวของลูกค้า """
    review = get_object_or_404(Review, id=review_id)

    if request.user.seller_profile != review.product.seller:
        messages.error(request, "You can only respond to reviews of your own products.")
        return redirect("seller_reviews")

    if request.method == "POST":
        response_text = request.POST.get("response_text")
        
        if ReviewResponse.objects.filter(review=review).exists():
            messages.error(request, "This review already has a response.")
        else:
            ReviewResponse.objects.create(review=review, seller=request.user.seller_profile, response_text=response_text)
            messages.success(request, "Response submitted successfully.")

    return redirect("seller_reviews")

from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from .models import MemberNotification

# @login_required
# def member_notifications_list(request):
#     """ แสดงหน้าแจ้งเตือนทั้งหมดของสมาชิก """
#     notifications = MemberNotification.objects.filter(user=request.user).order_by('-created_at')
    
#     # เพิ่ม debug เพื่อตรวจสอบข้อมูล
#     print(f"Debug - จำนวนการแจ้งเตือน: {notifications.count()}")
#     for notif in notifications[:5]:  # แสดงเฉพาะ 5 รายการแรกเพื่อไม่ให้ log มากเกินไป
#         print(f"Debug - แจ้งเตือน {notif.id}: {notif.message[:50]}...")
    
#     return render(request, "member_notifications.html", {"notifications": notifications})
    
# @login_required
# def api_member_notifications(request):
#     """ ส่งแจ้งเตือนของสมาชิกเป็น JSON (AJAX) """
#     notifications = MemberNotification.objects.filter(user=request.user, is_read=False).order_by("-created_at")[:10]
    
#     data = [
#         {"id": n.id, "message": n.message, "created_at": n.created_at.strftime("%Y-%m-%d %H:%M:%S")}
#         for n in notifications
#     ]
#     return JsonResponse({"notifications": data})

# @login_required
# def mark_notification_as_read(request):
#     if request.method == 'POST':
#         data = json.loads(request.body)
#         notification_id = data.get('notification_id')
        
#         if notification_id:
#             # Mark specific notification as read
#             notification = Notification.objects.get(id=notification_id, user=request.user)
#             notification.is_read = True
#             notification.save()
#         else:
#             # Mark all notifications as read
#             Notification.objects.filter(user=request.user).update(is_read=True)
            
#         return JsonResponse({'success': True})
    
#     return JsonResponse({'success': False}, status=400)

# @login_required
# def mark_all_notifications_as_read(request):
#     Notification.objects.filter(user=request.user).update(is_read=True)
#     return JsonResponse({'success': True})

# def create_notification(user, sender, notification_type, post=None, order=None, group_post=None):
#     message = ""
    
#     if notification_type == "like_post":
#         if post:
#             message = f"❤️ {sender.username} ถูกใจโพสต์ของคุณ!"
#         elif group_post:
#             message = f"❤️ {sender.username} ถูกใจโพสต์ของคุณในกลุ่ม!"
    
#     # เพิ่มประเภทการแจ้งเตือนอื่นๆ ตามต้องการ
    
#     # สร้างการแจ้งเตือน
#     MemberNotification.objects.create(
#         user=user,
#         message=message
#     )

# 1. แก้ไขฟังก์ชัน mark_notification_as_read ให้ใช้ MemberNotification แทน Notification
@login_required
def member_notifications_list(request):
    """ แสดงหน้าแจ้งเตือนทั้งหมดของสมาชิก """
    notifications = MemberNotification.objects.filter(user=request.user).order_by('-created_at')
    
    # เพิ่ม debug เพื่อตรวจสอบข้อมูล
    print(f"Debug - จำนวนการแจ้งเตือน: {notifications.count()}")
    for notif in notifications[:5]:  # แสดงเฉพาะ 5 รายการแรกเพื่อไม่ให้ log มากเกินไป
        print(f"Debug - แจ้งเตือน {notif.id}: {notif.message[:50]}...")
    
    return render(request, "member_notifications.html", {"notifications": notifications})

@login_required
def mark_notification_as_read(request):
    """ทำเครื่องหมายว่าอ่านแล้วสำหรับการแจ้งเตือนของสมาชิก"""
    if request.method == 'POST':
        # ตรวจสอบว่าเป็นการทำเครื่องหมายอ่านแล้วทั้งหมดหรือไม่
        mark_all = request.POST.get('mark_all')
        
        if mark_all:
            # ทำเครื่องหมายทั้งหมดว่าอ่านแล้ว
            MemberNotification.objects.filter(user=request.user).update(is_read=True)
            return JsonResponse({'success': True, 'message': 'ทำเครื่องหมายทั้งหมดแล้ว'})
        
        # ทำเครื่องหมายเฉพาะการแจ้งเตือนที่ระบุ
        notification_id = request.POST.get('notification_id')
        if notification_id:
            try:
                notification = MemberNotification.objects.get(id=notification_id, user=request.user)
                notification.is_read = True
                notification.save()
                return JsonResponse({'success': True, 'message': 'ทำเครื่องหมายแล้ว'})
            except MemberNotification.DoesNotExist:
                return JsonResponse({'success': False, 'message': 'ไม่พบการแจ้งเตือน'}, status=404)
    
    return JsonResponse({'success': False, 'message': 'คำขอไม่ถูกต้อง'}, status=400)

# 2. แก้ไขฟังก์ชัน api_member_notifications ให้รวมทั้งการแจ้งเตือนที่อ่านแล้วและยังไม่ได้อ่าน

@login_required
def api_member_notifications(request):
    """ส่งแจ้งเตือนของสมาชิกเป็น JSON (AJAX)"""
    # ดึงการแจ้งเตือนทั้งหมด ไม่เฉพาะแค่ที่ยังไม่ได้อ่าน
    notifications = MemberNotification.objects.filter(user=request.user).order_by("-created_at")[:20]
    
    data = [
        {
            "id": n.id, 
            "message": n.message, 
            "created_at": n.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "is_read": n.is_read
        }
        for n in notifications
    ]
    return JsonResponse({"notifications": data})

# 3. แก้ไขฟังก์ชัน create_notification ให้ใช้งานได้จริง

def create_notification(user, notification_type, sender=None, post=None, order=None, group_post=None):
    """สร้างการแจ้งเตือนใหม่"""
    message = ""

    if notification_type == "like_post":
        if post:
            message = f"❤️ {sender.username} ถูกใจโพสต์ของคุณ!"
        elif group_post:
            message = f"❤️ {sender.username} ถูกใจโพสต์ของคุณในกลุ่ม!"
    
    elif notification_type == "new_order":
        if order and order.user:
            message = f"🛒 คุณมีคำสั่งซื้อใหม่ #{order.id} จาก {order.user.username}"
        else:
            message = "🛒 คุณมีคำสั่งซื้อใหม่"
    
    elif notification_type == "comment":
        if post:
            message = f"💬 {sender.username} ได้แสดงความคิดเห็นต่อโพสต์ของคุณ"
        elif group_post:
            message = f"💬 {sender.username} ได้แสดงความคิดเห็นต่อโพสต์ของคุณในกลุ่ม"
    
    elif notification_type == "order_status":
        if order:
            message = f"📦 คำสั่งซื้อ #{order.id} ของคุณมีการเปลี่ยนแปลงสถานะเป็น {order.status}"
        else:
            message = "📦 สถานะคำสั่งซื้อของคุณมีการอัปเดต"

    # ✅ สร้างการแจ้งเตือน
    if hasattr(user, 'seller_profile'):
        SellerNotification.objects.create(
            seller=user,
            message=message
        )
    else:
        MemberNotification.objects.create(
            user=user,
            message=message
        )

    print(f"DEBUG: สร้างการแจ้งเตือน -> {message}")
    return message
