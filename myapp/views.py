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
from .models import Cart, CartItem  # ✅ Import Cart และ CartItem
from .models import Order, OrderItem  # ✅ เพิ่ม OrderItem เข้าไปด้วย

from .models import Member,CustomUser,SellerWallet, Post, Comment, CommunityGroup,PostMedia, GroupPost, Seller, Product, SavedPost, SavedGroupPost, GroupComment, Cart, ShippingAddress, Payment, Order, Review,RefundRequest 
from .forms import CustomUserCreationForm, ShippingAddressForm, SelleruserUpdateForm, SellerUpdateForm, SelleruserPasswordUpdateForm,UserChangeForm, PasswordChangeForm,EditPostForm, SellerForm, AccountEditForm, UserEditForm, PasswordChangeForm, CommunityGroupForm, ProductForm, SellerForm, SellerUpdateForm, UserCreationForm

User = get_user_model()  # ✅ ใช้ CustomUser แทน auth.User
from .models import Member,Payment,CustomUser, Post, Comment, CommunityGroup,PostMedia, GroupPost, Seller, Product, SavedPost, SavedGroupPost, GroupComment, Cart, ShippingAddress, Payment, Order, Review,RefundRequest 
from .forms import CustomUserCreationForm,CustomUserUpdateForm,PasswordChangeForm,SellerProfileUpdateForm, ShippingAddressForm, SelleruserUpdateForm, SellerUpdateForm, SelleruserPasswordUpdateForm,UserChangeForm, PasswordChangeForm,EditPostForm, SellerForm, AccountEditForm, UserEditForm, PasswordChangeForm, CommunityGroupForm, ProductForm, SellerForm, SellerUpdateForm, UserCreationForm
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

def all_posts(request):
    query = request.GET.get('query', '')  # รับค่าค้นหา
    if query:
        posts = Post.objects.filter(
            Q(content__icontains=query) |  # ค้นหาคำในเนื้อหาโพสต์
            Q(user__username__icontains=query)  # ค้นหาจากชื่อผู้ใช้
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

from django.db.models import Q
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from .models import Post, Follow, BlockedUser

@login_required
def home(request):
    """ 
    แสดงหน้า Home โดยกรองโพสต์ที่ถูกบล็อก, ถูกรีพอร์ต ยกเว้นโพสต์ของตัวเอง
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

    return render(request, 'home.html', {
        'username': request.user.username,
        'posts': posts,
        'following_users': following_users,
        'followed_users': followed_users
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

    return render(request, 'profile.html', {'user': user, 'posts': posts})



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

@login_required
def toggle_like(request, post_id):
    if request.method == "POST":
        post = get_object_or_404(Post, id=post_id)
        user = request.user  # ✅ ใช้ request.user ตรงๆ
        
        if post.likes.filter(id=user.id).exists():
            post.likes.remove(user)  # ✅ ถ้าเคยไลค์ -> กดอีกครั้งเพื่อลบ
            liked = False
        else:
            post.likes.add(user)  # ✅ ถ้ายังไม่เคยไลค์ -> กดไลค์
            liked = True

        like_count = post.likes.count()

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({"success": True, "liked": liked, "like_count": like_count})

        return redirect(request.META.get('HTTP_REFERER', 'home'))

    return JsonResponse({"success": False, "error": "Invalid request method"}, status=400)




@login_required
def post_detail(request, post_id):
    """ แสดงรายละเอียดโพสต์ """
    post = get_object_or_404(Post, id=post_id)
    return render(request, 'post_detail.html', {'post': post})

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
    
@login_required
def add_comment(request, post_id):
    post = get_object_or_404(Post, id=post_id)

    if request.method == "POST":
        content = request.POST.get('content')
        if content:
            comment = Comment.objects.create(post=post, user=request.user, content=content)
            return JsonResponse({
                'success': True,
                'message': 'Comment added successfully!',
                'username': request.user.username,  # ✅ ส่งชื่อผู้ใช้กลับไป
                'content': comment.content
            }, status=201)

        return JsonResponse({'success': False, 'message': 'Comment cannot be empty!'}, status=400)

    return JsonResponse({'success': False, 'message': 'Invalid request!'}, status=400)


@login_required
def community_list(request):
    """ แสดงรายการกลุ่ม Community สำหรับเฉพาะผู้ใช้ที่เป็น Member """
    if request.user.role != 'member':
        messages.error(request, "❌ เฉพาะสมาชิก (Member) เท่านั้นที่สามารถเข้าถึงหน้านี้!")
        return redirect('login')

    groups = CommunityGroup.objects.all()
    return render(request, 'community_list.html', {'groups': groups})

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

@login_required
def delete_group(request, group_id, post_id):
    """ ให้เจ้าของกลุ่มสามารถลบกลุ่ม """
    post = get_object_or_404(GroupPost, id=post_id, group=group, user=request.user)

    group = get_object_or_404(CommunityGroup, id=group_id, created_by=request.user)
    if request.method == "POST":
        post.delete()
        return JsonResponse({"success": True, "message": "โพสต์ถูกลบแล้ว!"})

    return JsonResponse({"success": False, "message": "Invalid request"}, status=400)
    return redirect('community_list')

from django.http import JsonResponse
@login_required
def group_detail(request, group_id):
    group = get_object_or_404(CommunityGroup, id=group_id)
    posts = GroupPost.objects.filter(group=group).order_by('-created_at')
    is_member = request.user in group.members.all()

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

    return render(request, 'group_detail.html', {
        'group': group,
        'posts': posts,
        'is_member': is_member
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
        create_notification(
            user=post.user,  # เจ้าของโพสต์
            sender=user,  # คนที่กดไลค์
            notification_type="like_post",
            group_post=post  # ✅ ใช้ `group_post` แทน `post`
        )

    return JsonResponse({
        'success': True,
        'liked': liked,
        'like_count': post.likes.count(),
    })


#เพิ่มคอมเม้นในกลุ่ม
import json
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.contrib.auth.decorators import login_required
from myapp.models import GroupPost, GroupComment

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
                    "message": "Comment added successfully!",
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


#อัพเดทโปรไฟล์
from .forms import AccountEditForm, PasswordChangeForm
@login_required
def profile_management(request):
    """ จัดการข้อมูลโปรไฟล์ของสมาชิก """
    profile = request.user.member_profile  # ✅ เชื่อมโยงกับ OneToOneField

    # ฟอร์มสำหรับแก้ไขข้อมูลส่วนตัว
    if request.method == 'POST' and 'update_personal_info' in request.POST:
        personal_info_form = AccountEditForm(request.POST, request.FILES, instance=profile)
        if personal_info_form.is_valid():
            personal_info_form.save()
            messages.success(request, "ข้อมูลโปรไฟล์ของคุณถูกแก้ไขเรียบร้อยแล้ว")
            return redirect('profile_management')
    else:
        personal_info_form = AccountEditForm(instance=profile)

    # ฟอร์มสำหรับเปลี่ยนรหัสผ่าน
    if request.method == 'POST' and 'change_password' in request.POST:
        password_form = PasswordChangeForm(user=request.user, data=request.POST)
        if password_form.is_valid():
            request.user.set_password(password_form.cleaned_data.get('new_password'))
            request.user.save()
            messages.success(request, "เปลี่ยนรหัสผ่านเรียบร้อยแล้ว")
            return redirect('profile_management')
    else:
        password_form = PasswordChangeForm(user=request.user)

    context = {
        'personal_info_form': personal_info_form,
        'password_form': password_form,
    }
    return render(request, 'profile_management.html', context)


@login_required
def profile_view(request, user_id):  # ✅ เพิ่ม user_id
    """ ดูโปรไฟล์ของสมาชิก """
    profile_user = get_object_or_404(User, id=user_id)  # ✅ ดึง User ตาม ID

    if profile_user.role != 'member':  # ✅ ใช้ profile_user แทน request.user
        messages.error(request, "❌ เฉพาะสมาชิก (Member) เท่านั้นที่สามารถเข้าถึงหน้านี้!")
        return redirect('login')

    # ถ้ากำลังดูโปรไฟล์ตัวเองให้ใช้ request.user
    user = request.user if request.user.id == user_id else profile_user

    try:
        member = Member.objects.get(user=profile_user)  # ✅ ดึงข้อมูลสมาชิกของ user ที่ดูโปรไฟล์
    except Member.DoesNotExist:
        member = None

    # ดึงโพสต์ของ user ที่กำลังดูโปรไฟล์
    posts = Post.objects.filter(
        user=profile_user,  # ✅ ต้องใช้ profile_user ไม่ใช่ request.user
        is_reported=False
    ).prefetch_related(
        'media',
        'comments',
        'likes'
    ).order_by('-created_at')

    # Debug information
    print(f"Debug - Viewing profile of User ID: {profile_user.id}")
    print(f"Debug - Total posts found: {posts.count()}")

    # คำนวณ following users
    following_users = [follow.following.id for follow in request.user.following.all()]

    return render(request, 'profile.html', {
        'posts': posts,
        'member': member,
        'user': profile_user,  # ✅ ส่ง user ที่กำลังดูโปรไฟล์ไปให้ template
        'following_users': following_users,
        'request_user': request.user  # ใช้เช็คปุ่ม follow
    })

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

# แชร์โพสต์ในกลุ่ม
@login_required
def share_group_post(request, post_id):
    post = get_object_or_404(GroupPost, id=post_id)
    group = post.group  # ใช้กลุ่มเดียวกันที่โพสต์อยู่

    # สร้างโพสต์ใหม่โดยคัดลอกเนื้อหาต้นฉบับ
    shared_post = GroupPost.objects.create(
        group=group,
        user=request.user,
        content=f"📢 Shared from {post.user.username}: {post.content}",
        shared_from=post  # เชื่อมโยงโพสต์ต้นฉบับ
    )

    # คัดลอกไฟล์สื่อ (ถ้ามี)
    for media in post.media.all():
        GroupPostMedia.objects.create(
            post=shared_post, 
            file=media.file, 
            media_type=media.media_type
        )

    return JsonResponse({
        'success': True,
        'message': "โพสต์ถูกแชร์แล้ว!",
        'post_id': shared_post.id
    }, status=201)




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

# ✅ ฟังก์ชันแดชบอร์ดผู้ขาย
@login_required
def seller_dashboard(request):
    seller = request.user.seller_profile
    products = seller.products.all()
    return render(request, "seller_dashboard.html", {"products": products, "seller": seller})


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

        # ✅ ตรวจสอบความถูกต้องของฟอร์ม
        if user_form.is_valid() and seller_form.is_valid():
            # ✅ ตรวจสอบว่าชื่อผู้ใช้ซ้ำหรือไม่
            username = user_form.cleaned_data.get("username")
            if User.objects.filter(username=username).exists():
                messages.error(request, "⚠️ ชื่อผู้ใช้นี้ถูกใช้แล้ว กรุณาเลือกชื่ออื่น!")
            else:
                # ✅ สร้าง User
                user = user_form.save(commit=False)
                user.role = 'seller'
                user.save()

                # ✅ ระบุ Authentication Backend
                user.backend = settings.AUTHENTICATION_BACKENDS[0]  

                # ✅ ตรวจสอบว่าผู้ใช้ได้อัปโหลดรูปภาพร้านค้าหรือไม่
                if not seller_form.cleaned_data.get("store_image"):
                    messages.error(request, "⚠️ กรุณาอัปโหลดรูปภาพร้านค้าก่อนสมัคร!")
                    return render(request, "register_seller.html", {
                        "user_form": user_form,
                        "seller_form": seller_form
                    })

                # ✅ สร้าง Seller Profile
                seller = seller_form.save(commit=False)
                seller.user = user
                seller.email = user.email
                seller.save()

                # ✅ ล็อกอินอัตโนมัติ
                login(request, user)
                messages.success(request, "🎉 สมัครเป็นผู้ขายสำเร็จ! ยินดีต้อนรับสู่แพลตฟอร์มของเรา!")
                return redirect("seller_dashboard")

        else:
            # ✅ ตรวจสอบว่ารหัสผ่านเป็นไปตามเงื่อนไขหรือไม่
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


# ✅ แสดงสินค้าของร้านค้าตนเอง (เฉพาะผู้ขาย)
@login_required
def my_products(request):
    # ตรวจสอบว่าผู้ใช้เป็น Seller หรือไม่
    seller = get_object_or_404(Seller, user=request.user)

    # ดึงข้อมูลร้านค้าของผู้ขาย
    store = seller  # สามารถใช้ `store` หรือ `seller` ตามที่ใช้ในเทมเพลต

    # ดึงสินค้าทั้งหมดของผู้ขาย
    products = Product.objects.filter(seller=seller)

    # คำนวณจำนวนสินค้าทั้งหมด และรายได้รวม
    total_products = products.count()
    total_earnings = sum(p.price * p.total_sold for p in products)

    context = {
        'seller': seller,
        'store': store,
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
def product_detail(request, product_id):
    product = get_object_or_404(Product, id=product_id)
    reviews = Review.objects.filter(product=product)  # ดึงรีวิวของสินค้า

    return render(request, 'product_detail.html', {
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


from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
from django.shortcuts import render, redirect
from .forms import CustomUserUpdateForm, SellerProfileUpdateForm

from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from .forms import CustomUserUpdateForm, SellerProfileUpdateForm

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

    return render(request, "seller/edit_profile.html", {
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

# ✅ แสดงรายละเอียดร้านค้า
def store_detail(request, store_id):
    store = Seller.objects.get(id=store_id)
    products = store.products.all()  # ดึงสินค้าทั้งหมดของร้านค้า
    return render(request, 'store_detail.html', {'store': store, 'products': products})

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

from myapp.models import Product, Review
from notifications.models import Notification  # ✅ แก้ไข Import


@login_required
def add_review(request, product_id):
    """ เพิ่มรีวิวสินค้า """
    product = get_object_or_404(Product, id=product_id)

    if request.method == "POST":
        rating = request.POST.get("rating")
        comment = request.POST.get("comment")
        review = Review.objects.create(user=request.user, product=product, rating=rating, comment=comment)

        # ✅ แจ้งเตือนเจ้าของร้านเมื่อมีรีวิวใหม่
        if product.seller:  # ตรวจสอบว่าเจ้าของสินค้ามีอยู่
            Notification.objects.create(
                user=product.seller,  # แจ้งเตือนเจ้าของร้าน
                sender=request.user,  # ผู้ที่ให้รีวิว
                notification_type="new_review",
                order=None,  # ไม่ได้เชื่อมกับออเดอร์
                post=None,
                group_post=None
            )

        messages.success(request, "✅ รีวิวสำเร็จ!")
        return redirect('product_detail', product_id=product.id)

    return render(request, "add_review.html", {"product": product})


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



from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from .models import Order, RefundRequest
from .forms import RefundRequestForm, RefundProofForm


from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from myapp.models import Order, RefundRequest

from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from myapp.models import Order, RefundRequest

@login_required
def order_history(request):
    """ แสดงประวัติคำสั่งซื้อของผู้ใช้ """
    orders = Order.objects.filter(user=request.user).order_by('-created_at')
    orders = Order.objects.filter(user=request.user).prefetch_related("order_items")
    pending_orders = orders.filter(status__in=["pending", "processing", "shipped"])
    completed_orders = orders.filter(status="delivered")
    cancelled_orders = orders.filter(status="cancelled")
    

    # ✅ ดึงรายการสินค้าที่รีวิวไปแล้ว
     # ✅ ดึงรายการสินค้าที่รีวิวไปแล้ว
    reviewed_products = Review.objects.filter(user=request.user).values_list("product_id", "order_id")
    reviewed_dict = {f"{product_id}_{order_id}": True for product_id, order_id in reviewed_products}

    
    return_orders = RefundRequest.objects.filter(user=request.user)

    context = {
        'orders': orders,
        'pending_orders': pending_orders,
        'completed_orders': completed_orders,
        'cancelled_orders': cancelled_orders,
        'reviewed_products': reviewed_dict,  # ✅ ใช้ dict เพื่อให้ template เช็คได้ง่าย
        'return_orders': return_orders,
        'all_orders': orders,  # ✅ เพิ่มออเดอร์ทั้งหมด
    }
    return render(request, 'order_history.html', context)



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

@login_required
def confirm_order(request):
    """ ยืนยันคำสั่งซื้อ และบันทึกข้อมูลที่อยู่จัดส่งลงฐานข้อมูล """
    if request.method == "POST":
        shipping_address_id = request.POST.get("shipping_address")
        shipping_address = get_object_or_404(ShippingAddress, id=shipping_address_id, user=request.user)

        cart = Cart.objects.get(user=request.user)
        cart_items = CartItem.objects.filter(cart=cart)

        if not cart_items:
            messages.error(request, "❌ ไม่มีสินค้าในตะกร้า กรุณาเลือกสินค้าก่อนทำการสั่งซื้อ!")
            return redirect("cart")

        orders_by_seller = {}
        for item in cart_items:
            seller = item.product.seller
            if seller not in orders_by_seller:
                orders_by_seller[seller] = []
            orders_by_seller[seller].append(item)

        order_ids = []

        for seller, items in orders_by_seller.items():
            total_price = sum(item.quantity * item.product.price for item in items)

            # ✅ ตรวจสอบให้แน่ใจว่ามีการเก็บค่าทั้งหมด
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

            order_ids.append(order.id)

        cart_items.delete()
        messages.success(request, "✅ คำสั่งซื้อของคุณถูกยืนยันเรียบร้อยแล้ว!")

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
    seller = getattr(request.user, "seller_profile", None)

    if not seller:
        return render(request, "seller_orders.html", {"orders": []})  # ไม่มีข้อมูลผู้ขาย

    # ✅ ดึง `OrderItem` และ `Product` มาพร้อมกับคำสั่งซื้อ
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
    orders = Order.objects.filter(seller=request.user.seller_profile, payment_status="pending")

    return render(request, "seller_payment_verification.html", {
        "orders": orders
    })



#@login_required
#def approve_seller_payment(request, order_id):
    #""" ✅ อนุมัติการชำระเงิน """
    #order = get_object_or_404(Order, id=order_id, seller=request.user.seller_profile)

    #if order.payment_status == 'pending':
       # order.payment_status = 'paid'
      #  order.status = 'processing'
       # order.save()
       # messages.success(request, f"✅ อนุมัติการชำระเงินสำหรับออเดอร์ #{order.id}")

   # return JsonResponse({'success': True, 'message': f'ออเดอร์ #{order.id} อนุมัติเรียบร้อย'})

@login_required
def reject_seller_payment(request, order_id):
    """ ❌ ปฏิเสธการชำระเงิน """
    order = get_object_or_404(Order, id=order_id, seller=request.user.seller_profile)

    order.payment_status = "rejected"
    order.save()

    messages.error(request, f"❌ ออเดอร์ #{order.id} ถูกปฏิเสธ")
    return JsonResponse({"success": True, "message": f"ออเดอร์ #{order.id} ถูกปฏิเสธแล้ว!"})

from .models import Follow, CustomUser
# ✅ สร้างฟังก์ชันสำหรับการติดตามผู้ใช้
from .models import Follow, CustomUser
# ✅ สร้างฟังก์ชันสำหรับการติดตามผู้ใช้
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404
from .models import Follow, CustomUser  # ใช้ CustomUser แทน User

@login_required
def follow_user(request, user_id):
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

    # ✅ ดึงค่าล่าสุดจาก Database
    followers_count = Follow.objects.filter(following=target_user).count()
    following_count = Follow.objects.filter(follower=request.user).count()

    return JsonResponse({
        "success": True,
        "is_following": is_following,
        "followers_count": followers_count,
        "following_count": following_count
    })

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

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import get_object_or_404
import os
from django.conf import settings
from .models import GroupPostMedia

@login_required
def edit_group_post(request, post_id):
    post = get_object_or_404(GroupPost, id=post_id, user=request.user)

    if request.method == "POST":
        content = request.POST.get("content", "").strip()
        images = request.FILES.getlist("images")
        videos = request.FILES.getlist("videos")

        # ✅ อัปเดตเนื้อหาโพสต์
        post.content = content
        post.save()

        # ✅ ลบไฟล์ที่ผู้ใช้เลือก
        delete_media_ids = request.POST.getlist("delete_media")
        GroupPostMedia.objects.filter(id__in=delete_media_ids, post=post).delete()

        # ✅ เพิ่มไฟล์ใหม่
        for image in images:
            GroupPostMedia.objects.create(post=post, file=image, media_type="image")

        for video in videos:
            GroupPostMedia.objects.create(post=post, file=video, media_type="video")

        return redirect('group_post_detail', post_id=post.id)


from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from .models import Comment

# ✅ ลบคอมเมนต์
@login_required
def delete_comment(request, comment_id):
    comment = get_object_or_404(Comment, id=comment_id, user=request.user)

    if request.method == "POST":
        comment.delete()
        return JsonResponse({"success": True, "message": "คอมเมนต์ถูกลบเรียบร้อยแล้ว"}, status=200)

    return JsonResponse({"success": False, "message": "Invalid request"}, status=400)

# ✅ แก้ไขคอมเมนต์
from .models import Comment
from .forms import CommentForm
@login_required
def edit_comment(request, comment_id):
    comment = get_object_or_404(Comment, id=comment_id, user=request.user)

    if request.method == "POST":
        content = request.POST.get("content")
        if content:
            comment.content = content
            comment.save()
            return JsonResponse({"success": True, "message": "Comment updated!", "content": comment.content})
        return JsonResponse({"success": False, "message": "Comment cannot be empty!"}, status=400)

    return JsonResponse({"success": False, "message": "Invalid request!"}, status=400)


'''@login_required
def profile_view(request):
    user = request.user
    followers_count = user.followers.count()
    following_count = user.following.count()
    is_following = Follow.objects.filter(follower=request.user, following=user).exists()

    return render(request, 'profile.html', {
        'user': user,
        'followers_count': followers_count,
        'following_count': following_count,
        'is_following': is_following
    }) '''


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
    
    return redirect('seller_orders')  # 🔄 เปลี่ยนเส้นทางกลับไปที่หน้า seller_orders


from .models import Report
from .forms import ReportForm
@login_required
def report_post(request, post_id):
    post = get_object_or_404(Post, id=post_id)

    # ✅ ป้องกันไม่ให้ผู้ใช้รีพอร์ตโพสต์ของตัวเอง
    if post.user == request.user:
        messages.error(request, "❌ คุณไม่สามารถรีพอร์ตโพสต์ของตัวเองได้!")
        return redirect('home')

    if request.method == 'POST':
        form = ReportForm(request.POST)
        if form.is_valid():
            Report.objects.create(
                post=post,
                reported_by=request.user,
                reason=form.cleaned_data['reason'],
                description=form.cleaned_data['description']
            )
            post.is_reported = True  # ✅ ซ่อนโพสต์ที่ถูกรายงาน
            post.save()
            messages.success(request, "Post reported successfully.")
            return redirect('block_user', post.user.id)  # ✅ นำไปสู่หน้าบล็อคผู้ใช้
    else:
        form = ReportForm()
    return render(request, 'report_post.html', {'form': form, 'post': post})

from.models import BlockedUser
@login_required
def block_user(request, user_id):
    blocked_user = get_object_or_404(User, id=user_id)

    if blocked_user == request.user:
        messages.error(request, "❌ คุณไม่สามารถบล็อกตัวเองได้!")
        return redirect('home')

    if request.method == 'POST':
        BlockedUser.objects.create(blocked_by=request.user, blocked_user=blocked_user)
        messages.success(request, f"✅ คุณได้บล็อก {blocked_user.username} แล้ว")
        return redirect('home')

    return render(request, 'block_user.html', {'blocked_user': blocked_user})



from django.contrib.auth.decorators import user_passes_test
from django.contrib.auth import authenticate, login
from django.contrib import messages
from.forms import AdminRegisterForm
# ตรวจสอบว่าเป็นแอดมินหรือไม่
def is_admin(user):
    return user.is_authenticated and user.is_staff

# แอดมินล็อกอิน
def admin_login(request):
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]
        user = authenticate(request, username=username, password=password)
        if user is not None and user.is_staff:  # ✅ ต้องเป็นแอดมินเท่านั้น
            login(request, user)
            return redirect("admin_dashboard")
        else:
            messages.error(request, "Invalid credentials or not an admin.")
    
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

# แสดงแดชบอร์ดแอดมิน
# แสดงแดชบอร์ดแอดมิน (เฉพาะแอดมินเข้าได้)
@user_passes_test(is_admin, login_url='/login/')
def admin_dashboard(request):
    reported_posts = Report.objects.select_related('post', 'reported_by').order_by('-created_at')
    return render(request, "admin_dashboard.html", {"reported_posts": reported_posts})

# ลบโพสต์ที่ถูกรีพอร์ต
@user_passes_test(is_admin)
def delete_reported_post(request, post_id):
    post = Post.objects.filter(id=post_id).first()
    if post:
        post.delete()
        messages.success(request, "Post has been deleted.")
    return redirect("admin_dashboard")

from django.contrib.auth.views import PasswordResetView
from django.urls import reverse_lazy

class CustomPasswordResetView(PasswordResetView):
    template_name = 'password_reset.html'  # ฟอร์มขอรหัสผ่านใหม่
    email_template_name = 'password_reset_email.html'  # เทมเพลตรูปแบบอีเมล
    subject_template_name = 'password_reset_subject.txt'  # หัวข้ออีเมล
    success_url = reverse_lazy('password_reset_done')  # หลังส่งอีเมลเสร็จให้ไปหน้านี้

@login_required
def get_group_posts(request, group_id):
    group = get_object_or_404(CommunityGroup, id=group_id)
    posts = GroupPost.objects.filter(group=group).order_by('-created_at')

    post_list = []
    for post in posts:
        post_list.append({
            'id': post.id,
            'username': post.user.username,
            'profile_picture': post.user.member_profile.profile_picture.url if post.user.member_profile.profile_picture else None,
            'content': post.content,
            'created_at': post.created_at.strftime('%b %d, %Y %H:%M'),
            'image_url': post.image.url if post.image else None,
            'video_url': post.video.url if post.video else None,
            'is_owner': request.user == post.user  # ✅ ตรวจสอบว่าผู้ใช้เป็นเจ้าของโพสต์หรือไม่
        })

    return JsonResponse({'posts': post_list}, status=200)


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

from django.shortcuts import render, get_object_or_404, redirect
from myapp.models import Product, Review, ReviewMedia

@login_required
def add_review(request, order_id, product_id):
    """ ✅ ให้รีวิวสินค้าได้เฉพาะเมื่อออเดอร์จัดส่งสำเร็จ และไม่สามารถรีวิวซ้ำได้ """
    order = get_object_or_404(Order, id=order_id, user=request.user, status="delivered")
    product = get_object_or_404(Product, id=product_id)

    # ✅ เช็คว่ารีวิวสินค้านี้ไปแล้วหรือยัง
    existing_review = Review.objects.filter(user=request.user, product=product, order=order).exists()
    if existing_review:
        messages.error(request, "⚠️ คุณได้รีวิวสินค้านี้ไปแล้ว!")
        return redirect("order_history")

    if request.method == "GET":
        return render(request, "add_review.html", {"product": product, "order": order})

    if request.method == "POST":
        rating = request.POST.get("rating")
        comment = request.POST.get("comment")
        media_files = request.FILES.getlist("media")

        if not rating or not comment:
            messages.error(request, "⚠️ กรุณากรอกคะแนนและรีวิว")
            return redirect("add_review", order_id=order.id, product_id=product.id)

        # ✅ บันทึกรีวิว และเชื่อมโยงกับออเดอร์
        review = Review.objects.create(
            user=request.user, 
            product=product, 
            order=order,  # ✅ เพิ่ม `order` เข้าไป
            rating=int(rating), 
            comment=comment
        )

        for file in media_files:
            media_type = "image" if file.content_type.startswith("image") else "video"
            ReviewMedia.objects.create(review=review, file=file, media_type=media_type)

        messages.success(request, "✅ รีวิวของคุณถูกบันทึกเรียบร้อย!")
        return redirect("product_detail", product_id=product.id)

    return JsonResponse({"success": False, "message": "❌ Method Not Allowed"}, status=405)




def seller_wallet(request):
    """ แสดงข้อมูลกระเป๋าเงินของผู้ขาย """
    seller = request.user.seller_profile
    wallet, created = SellerWallet.objects.get_or_create(seller=seller)
    withdrawals = WithdrawalRequest.objects.filter(seller=seller).order_by('-created_at')

    return render(request, 'seller_wallet.html', {'wallet': wallet, 'withdrawals': withdrawals})


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
def request_refund(request, order_id, item_id):
    """ ฟังก์ชันให้ผู้ใช้ขอคืนเงินสำหรับสินค้ารายการเดียว """
    order = get_object_or_404(Order, id=order_id, user=request.user)
    item = get_object_or_404(OrderItem, id=item_id, order=order)  # ✅ ดึงสินค้าเฉพาะที่ตรงกับออเดอร์

    if RefundRequest.objects.filter(order=order, item=item).exists():
        messages.warning(request, "คุณได้ส่งคำขอคืนเงินสำหรับสินค้านี้ไปแล้ว")
        return redirect("order_history")

    if request.method == "POST":
        refund_request = RefundRequest.objects.create(
            user=request.user,
            order=order,
            item=item,  # ✅ บันทึกสินค้าที่ขอคืนเงิน
            account_name=request.POST.get("account_name"),
            account_number=request.POST.get("account_number"),
            bank_name=request.POST.get("bank_name"),
            refund_reason=request.POST.get("refund_reason"),
            payment_proof=request.FILES.get("payment_proof"),
            status="pending",
        )

        messages.success(request, "✅ คำขอคืนเงินถูกส่งเรียบร้อยแล้ว")
        return redirect("order_history")

    return render(request, "partials/refund_request.html", {"order": order, "item": item})





@login_required
def seller_refund_requests(request):
    """ แสดงรายการคำขอคืนเงินของผู้ขาย """
    seller = request.user.seller_profile  # ดึงโปรไฟล์ของผู้ขาย
    refund_requests = RefundRequest.objects.filter(order__seller=seller)\
                                           .select_related("order", "user", "item", "item__product")\
                                           .prefetch_related("order__order_items", "order__order_items__product")
    return render(request, "refund_requests_seller.html", {"refund_requests": refund_requests})




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
@login_required
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
    """ แสดงรายงานสถิติการขายของผู้ขาย """
    seller = request.user.seller_profile  # สมมติว่า user มี OneToOneField กับ Seller

    # ✅ รายได้รวมจากคำสั่งซื้อที่เสร็จสมบูรณ์
        # ✅ ตรวจสอบว่ามีคำสั่งซื้อที่เสร็จสมบูรณ์หรือไม่
    total_sales = Order.objects.filter(seller=seller, status="delivered").aggregate(Sum("total_price"))["total_price__sum"] or 0


    # ✅ สินค้าขายดี (Top 5) - แก้ไขตรงนี้
    top_products = (
        Product.objects.filter(seller=seller)
        .annotate(total_sold_count=Sum("orderitem__quantity"))  # แก้จาก order_items เป็น orderitem
        .order_by("-total_sold_count")[:5]
    )

    # ✅ จำนวนการคืนสินค้า
    refunds = RefundRequest.objects.filter(order__seller=seller).count()

    # ✅ คะแนนรีวิวเฉลี่ย
    avg_rating = Review.objects.filter(product__seller=seller).aggregate(Avg("rating"))["rating__avg"] or 0

    # ✅ รีวิวล่าสุด (5 รีวิว)
    recent_reviews = Review.objects.filter(product__seller=seller).order_by("-created_at")[:5]

    context = {
        "total_sales": total_sales,
        "top_products": top_products,
        "refunds": refunds,
        "avg_rating": avg_rating,
        "recent_reviews": recent_reviews,
    }

    return render(request, "seller_performance.html", context)

def is_admin(user):
    return user.is_staff  # ✅ อนุญาตเฉพาะแอดมิน

@user_passes_test(is_admin)
def admin_performance(request):
    """ แสดงรายงานสถิติของผู้ขายทั้งหมด """

    # ✅ ยอดขายรวมทั้งหมด
    total_sales = Order.objects.filter(status="delivered").aggregate(Sum("total_price"))["total_price__sum"] or 0

    # ✅ ยอดขายรายเดือน
    sales_by_month = (
        Order.objects.filter(status="delivered")
        .values("created_at__year", "created_at__month")
        .annotate(total_sales=Sum("total_price"))
        .order_by("created_at__year", "created_at__month")
    )

    # ✅ ผู้ขายที่มียอดขายสูงสุด
    top_sellers = (
        Seller.objects.annotate(total_revenue=Sum("orders__total_price"))
        .order_by("-total_revenue")[:5]
    )

    # ✅ การคืนสินค้ารายเดือน
    refunds_by_month = (
        RefundRequest.objects.values("created_at__year", "created_at__month")
        .annotate(total_refunds=Count("id"))
        .order_by("created_at__year", "created_at__month")
    )

    context = {
        "total_sales": total_sales,
        "sales_by_month": list(sales_by_month),
        "top_sellers": top_sellers,
        "refunds_by_month": list(refunds_by_month),
    }

    return render(request, "admin_performance.html", context)

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
