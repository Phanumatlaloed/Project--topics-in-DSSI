from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt  # ✅ เพิ่มการ import
from django.contrib.auth import get_user_model, update_session_auth_hash
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.utils import timezone
import os
from django.db.models import Q
from django.middleware.csrf import get_token
from .models import Cart, CartItem  # ✅ Import Cart และ CartItem
from .models import Order, OrderItem  # ✅ เพิ่ม OrderItem เข้าไปด้วย

from .models import Member,CustomUser, Post, Comment, CommunityGroup,PostMedia, GroupPost, Seller, Product, SavedPost, SavedGroupPost, GroupComment, Cart, ShippingAddress, Payment, Order, Review,RefundRequest 
from .forms import CustomUserCreationForm,ShippingAddressForm,SelleruserUpdateForm, SellerUpdateForm, SelleruserPasswordUpdateForm,UserChangeForm, PasswordChangeForm,EditPostForm, SellerForm, AccountEditForm, UserEditForm, PasswordChangeForm, CommunityGroupForm, ProductForm, SellerForm, SellerUpdateForm, UserCreationForm

User = get_user_model()  # ✅ ใช้ CustomUser แทน auth.User


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

        # สร้าง User
        user = CustomUser.objects.create_user(
            username=username,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
            role='member'
        )

        # สร้างโปรไฟล์ Member
        Member.objects.create(user=user, gender=gender, date_of_birth=date_of_birth)

        messages.success(request, "สมัครสมาชิกสำเร็จ! กรุณาเข้าสู่ระบบ")
        return redirect("login")

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

    return render(request, "all_posts.html", {"posts": posts, "query": query})

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

@login_required
def home(request):
    """ แสดงหน้า Home สำหรับเฉพาะผู้ใช้ที่เป็น Member """
    if request.user.role != 'member':
        messages.error(request, "❌ เฉพาะสมาชิก (Member) เท่านั้นที่สามารถเข้าถึงหน้านี้!")
        return redirect('login')  # ✅ รีไดเรกต์ไปที่หน้า login ถ้าไม่ใช่ member

    return render(request, 'home.html', {
        'username': request.user.username,  
        'posts': Post.objects.all().order_by('-created_at')  # ✅ ส่งโพสต์ไปแสดงในหน้า home
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

#savelist
def savelist(request):
    return render(request, 'savelist.html')

def profile(request):
    if request.method == 'POST':
        user = request.user
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

    return render(request, 'profile.html', {'user': request.user})


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

'''@csrf_exempt
def create_post(request):
    if request.method == 'POST':
        print("Request body:", request.body)
        print("Authenticated user:", request.user.is_authenticated)
    # โค้ดส่วนที่เหลือ'''
    




def logout_view(request):
    logout(request)
    messages.success(request, "คุณได้ออกจากระบบเรียบร้อยแล้ว")
    return redirect('login')

@login_required
def create_post(request):
    if request.method == "POST":
        content = request.POST.get('content', '').strip()
        image_files = request.FILES.getlist('images')
        video_files = request.FILES.getlist('videos')

        if not content and not image_files and not video_files:
            return JsonResponse({'success': False, 'message': 'โพสต์ต้องมีข้อความ หรือไฟล์สื่อ'}, status=400)

        post = Post.objects.create(user=request.user, content=content)

        for img in image_files:
            PostMedia.objects.create(post=post, file=img, media_type='image')

        for vid in video_files:
            PostMedia.objects.create(post=post, file=vid, media_type='video')

        return JsonResponse({'success': True, 'post_id': post.id}, status=201)

    return JsonResponse({'success': False, 'message': 'Invalid request'}, status=400)

@login_required
def delete_post(request, post_id):
    """ ฟังก์ชันลบโพสต์และไฟล์แนบที่เกี่ยวข้อง """
    post = Post.objects.filter(id=post_id).first()  # ✅ ใช้ `.filter().first()` เพื่อลด error

    if not post:
        return JsonResponse({"success": False, "message": "โพสต์นี้ถูกลบไปแล้วหรือไม่มีอยู่จริง"}, status=404)

    # ✅ ตรวจสอบว่าเป็นเจ้าของโพสต์
    if post.user != request.user:
        return JsonResponse({"success": False, "message": "คุณไม่มีสิทธิ์ลบโพสต์นี้"}, status=403)

    # ✅ ลบไฟล์แนบ
    for media in post.media.all():
        if media.file:
            file_path = os.path.join(settings.MEDIA_ROOT, str(media.file))
            if os.path.exists(file_path):
                os.remove(file_path)
        media.delete()

    post.delete()  # ✅ ลบโพสต์
    return JsonResponse({"success": True, "message": "โพสต์ถูกลบเรียบร้อยแล้ว!"}, status=200)


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


@csrf_exempt  # ❌ ปิด CSRF สำหรับฟังก์ชันนี้
@login_required
def delete_media(request, media_id):
    """ ฟังก์ชันลบไฟล์สื่อออกจากโพสต์ """
    if request.method == "DELETE":
        media = get_object_or_404(PostMedia, id=media_id)

        if media.post.user != request.user:
            return JsonResponse({"success": False, "message": "คุณไม่มีสิทธิ์ลบไฟล์นี้"}, status=403)

        media.delete()
        return JsonResponse({"success": True, "message": "ไฟล์ถูกลบเรียบร้อยแล้ว!"})

    return JsonResponse({"success": False, "message": "Invalid request"}, status=400)


@login_required
def toggle_like(request, post_id):
    if request.method == "POST":
        try:
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

        except Exception as e:
            print(f"❌ Error: {e}")
            return JsonResponse({"success": False, "error": str(e)}, status=500)

    return JsonResponse({"success": False, "error": "Invalid request method"}, status=400)

@login_required
def post_detail(request, post_id):
    """ แสดงรายละเอียดโพสต์ """
    post = get_object_or_404(Post, id=post_id)
    return render(request, 'post_detail.html', {'post': post})

@login_required
def savelist(request):
    """ แสดงโพสต์ที่ถูกบันทึกโดยผู้ใช้ (เฉพาะ Member เท่านั้น) """
    if request.user.role != 'member':
        messages.error(request, "❌ เฉพาะสมาชิก (Member) เท่านั้นที่สามารถเข้าถึงหน้านี้!")
        return redirect('login')

    saved_posts = SavedPost.objects.filter(user=request.user)  # ✅ ใช้ `CustomUser`
    return render(request, "savelist.html", {"saved_posts": saved_posts})


@login_required
def save_post(request, post_id):
    """ ฟังก์ชันบันทึก/ลบโพสต์จากรายการบันทึก """
    post = get_object_or_404(Post, id=post_id)
    user = request.user  

    saved_post, created = SavedPost.objects.get_or_create(user=user, post=post)

    if not created:
        saved_post.delete()
        saved = False
    else:
        saved = True

    # ✅ ตรวจสอบว่าเป็น AJAX Request
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({
            "success": True,
            "saved": saved,
        })

    return redirect(request.META.get('HTTP_REFERER', '/'))

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


def profile_management(request):
    profile = request.user.profile
    if request.method == 'POST':
        user_form = UserEditForm(request.POST, instance=request.user)
        profile_form = AccountEditForm(request.POST, request.FILES, instance=profile)
        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()
            profile_form.save()
            messages.success(request, "ข้อมูลโปรไฟล์ของคุณถูกแก้ไขเรียบร้อยแล้ว")
            return redirect('profile_management')
    else:
        user_form = UserEditForm(instance=request.user)
        profile_form = AccountEditForm(instance=profile)

    return render(request, 'profile_management.html', {
        'user_form': user_form,
        'profile_form': profile_form,
    })


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
def delete_group(request, group_id):
    """ ให้เจ้าของกลุ่มสามารถลบกลุ่ม """
    group = get_object_or_404(CommunityGroup, id=group_id, created_by=request.user)
    group.delete()
    messages.success(request, "กลุ่มถูกลบเรียบร้อยแล้ว!")
    return redirect('community_list')

@login_required
def group_detail(request, group_id):
    group = get_object_or_404(CommunityGroup, id=group_id)
    posts = GroupPost.objects.filter(group=group).order_by('-created_at')
    is_member = request.user in group.members.all()

    if request.method == "POST":
        content = request.POST.get('content', '')
        image = request.FILES.get('image')
        video = request.FILES.get('video')

        if content or image or video:
            GroupPost.objects.create(
                group=group,
                user=request.user,  # ✅ ใช้ request.user (User instance)
                content=content,
                image=image,
                video=video
            )
            return redirect('group_detail', group_id=group.id)

    return render(request, 'group_detail.html', {
        'group': group,
        'posts': posts,
        'is_member': is_member
    })


@login_required
def join_group(request, group_id):
    group = get_object_or_404(CommunityGroup, id=group_id)
    if request.user not in group.members.all():
        group.members.add(request.user)
        messages.success(request, "You have joined the group!")
    else:
        messages.info(request, "You are already a member of this group.")
    return redirect('group_detail', group_id=group.id)


@login_required
def toggle_group_post_like(request, post_id):
    """
    Toggle the like status for a group post.
    """
    post = get_object_or_404(GroupPost, id=post_id)
    user = request.user  # ✅ ใช้ request.user โดยตรง

    if post.likes.filter(id=user.id).exists():
        post.likes.remove(user)  # ✅ ใช้ User
        liked = False
    else:
        post.likes.add(user)  # ✅ ใช้ User
        liked = True

    return JsonResponse({
        'success': True,
        'liked': liked,
        'like_count': post.likes.count(),
    })


@login_required
def add_group_post_comment(request, post_id):
    post = get_object_or_404(GroupPost, id=post_id)

    if request.method == "POST":
        content = request.POST.get("content")
        if content:
            comment = GroupComment.objects.create(
                post=post, user=request.user, content=content
            )
            return JsonResponse(
                {
                    "success": True,
                    "message": "Comment added successfully!",
                    "comment": {
                        "user": comment.user.username,
                        "content": comment.content,
                        "created_at": comment.created_at.strftime(
                            "%Y-%m-%d %H:%M:%S"
                        ),
                    },
                },
                status=201,
            )
        return JsonResponse({"success": False, "message": "Comment cannot be empty!"}, status=400)

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
def profile_view(request):
    """ ดูโปรไฟล์ของสมาชิก """
    if request.user.role != 'member':
        messages.error(request, "❌ เฉพาะสมาชิก (Member) เท่านั้นที่สามารถเข้าถึงหน้านี้!")
        return redirect('login')

    user = request.user  
    try:
        member = Member.objects.get(user=user)  # ✅ ดึง Member Profile
    except Member.DoesNotExist:
        member = None  # ✅ ป้องกันกรณีไม่มีโปรไฟล์
    
    posts = Post.objects.filter(user=user).order_by('-created_at')  

    return render(request, 'profile.html', {
        'posts': posts,
        'member': member,
        'user': user,
    })


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

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import GroupPost, SavedGroupPost, Member

@login_required
def save_group_post(request, post_id):
    """
    ฟังก์ชันสำหรับ Save / Unsave Group Post
    """
    post = get_object_or_404(GroupPost, id=post_id)
    user_profile = get_object_or_404(Member, user=request.user)  # ตรวจสอบโปรไฟล์

    saved_post, created = SavedGroupPost.objects.get_or_create(user=user_profile, post=post)

    if not created:
        saved_post.delete()
        saved = False
    else:
        saved = True

    return JsonResponse({
        'success': True,
        'saved': saved,
        'save_count': post.saves.count(),
    })




@login_required
def share_group_post(request, post_id):
    """
    แชร์โพสต์ในกลุ่ม (GroupPost) ไปยังกลุ่มอื่น
    """
    post = get_object_or_404(GroupPost, id=post_id)

    group_id = request.POST.get("group_id")
    if not group_id:
        return JsonResponse({'success': False, 'error': 'Group ID is required'}, status=400)

    group = get_object_or_404(CommunityGroup, id=group_id)

    GroupPost.objects.create(
        group=group,
        user=request.user,
        content=f"📢 Shared from {post.group.name}:\n{post.content}",
        image=post.image,
        video=post.video,
        shared_from=post
    )

    return JsonResponse({
        'success': True,
        'message': f"Post shared to {group.name}!",
    })


login_required
def edit_group_post(request, post_id):
    """ แก้ไขโพสต์เฉพาะเจ้าของโพสต์ """
    post = get_object_or_404(GroupPost, id=post_id, user=request.user)

    if request.method == 'POST':
        post.content = request.POST.get('content', post.content)
        post.image = request.FILES.get('image', post.image)
        post.video = request.FILES.get('video', post.video)
        post.save()
        return redirect('group_detail', group_id=post.group.id)

    return render(request, 'edit_post.html', {'post': post})


@login_required
def delete_group_post(request, post_id):
    """ ลบโพสต์เฉพาะเจ้าของโพสต์ """
    post = get_object_or_404(GroupPost, id=post_id, user=request.user)
    if request.method == "POST":
        post.delete()
        return JsonResponse({"success": True, "message": "Post deleted successfully!"})
    return JsonResponse({"success": False, "message": "Invalid request"}, status=400)


@login_required
def save_group_post(request, post_id):
    """ บันทึกโพสต์จากกลุ่ม """
    post = get_object_or_404(GroupPost, id=post_id)

    # ตรวจสอบว่ามีการบันทึกโพสต์ไปแล้วหรือไม่
    saved_post, created = SavedPost.objects.get_or_create(
        user=request.user,
        post=post,
        post_type="group"
    )

    if not created:
        saved_post.delete()  # กดยกเลิกการบันทึก
        return JsonResponse({"success": True, "message": "Post removed from saved list!"})

    return JsonResponse({"success": True, "message": "Post saved successfully!"})




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

@login_required
def edit_product(request, product_id):
    """ แก้ไขสินค้า """
    product = get_object_or_404(Product, id=product_id, seller=request.user.seller_profile)
    if request.method == "POST":
        form = ProductForm(request.POST, request.FILES, instance=product)
        if form.is_valid():
            form.save()
            messages.success(request, "Product updated successfully!")
            return redirect("seller_dashboard")
    else:
        form = ProductForm(instance=product)
    return render(request, "edit_product.html", {"form": form})

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
    seller = get_object_or_404(Seller, user=request.user)
    products = seller.products.all()
    return render(request, "my_products.html", {"products": products, "seller": seller})

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






@login_required
def product_detail(request, product_id):
    """ แสดงรายละเอียดสินค้า """
    product = get_object_or_404(Product, id=product_id)
    return render(request, "product_detail.html", {"product": product})


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


from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404

@login_required
def edit_seller_profile(request):
    """ แก้ไขโปรไฟล์ผู้ขาย (User + Seller + รหัสผ่าน) """
    seller = get_object_or_404(Seller, user=request.user)

    # ✅ กำหนดค่าเริ่มต้น
    user_form = SelleruserUpdateForm(instance=request.user)
    seller_form = SellerUpdateForm(instance=seller)
    password_form = SelleruserPasswordUpdateForm(request.user)

    if request.method == 'POST':
        if 'update_profile' in request.POST:
            user_form = SelleruserUpdateForm(request.POST, instance=request.user)
            seller_form = SellerUpdateForm(request.POST, request.FILES, instance=seller)

            if user_form.is_valid() and seller_form.is_valid():
                user_form.save()
                seller_form.save()
                messages.success(request, "✅ โปรไฟล์ของคุณอัปเดตเรียบร้อยแล้ว!")
                return redirect('edit_seller_profile')

        elif 'change_password' in request.POST:
            password_form = SelleruserPasswordUpdateForm(user=request.user, data=request.POST)
            if password_form.is_valid():
                user = password_form.user
                user.set_password(password_form.cleaned_data['new_password1'])  # ✅ ใช้ `set_password()`
                user.save()
                update_session_auth_hash(request, user)  # ✅ ป้องกันการล็อกเอาต์
                messages.success(request, "🔑 เปลี่ยนรหัสผ่านสำเร็จ!")
                return redirect('edit_seller_profile')
            else:
                messages.error(request, "❌ กรุณาตรวจสอบข้อมูลรหัสผ่านใหม่")

    return render(request, 'edit_seller_profile.html', {
        'user_form': user_form,
        'seller_form': seller_form,
        'password_form': password_form
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

@login_required
def view_cart(request):
    """ แสดงสินค้าที่อยู่ในตะกร้า """
    cart, created = Cart.objects.get_or_create(user=request.user)
    cart_items = CartItem.objects.filter(cart=cart)
    total_price = sum(item.total_price() for item in cart_items)

    return render(request, "cart.html", {
        "cart_items": cart_items,
        "total_price": total_price
    })

@login_required
def add_to_cart(request, product_id):
    """ เพิ่มสินค้าในตะกร้า """
    product = get_object_or_404(Product, id=product_id)
    
    # ✅ ค้นหาหรือลงทะเบียนตะกร้าสำหรับผู้ใช้
    cart, created = Cart.objects.get_or_create(user=request.user)

    # ✅ เพิ่มหรืออัปเดตจำนวนสินค้าในตะกร้า
    cart_item, created = CartItem.objects.get_or_create(cart=cart, product=product)

    if not created:
        cart_item.quantity += 1
        cart_item.save()

    messages.success(request, "✅ เพิ่มสินค้าในตะกร้าเรียบร้อย!")
    return redirect('cart')

@login_required
def update_cart(request, item_id, action):
    """ เพิ่ม / ลด จำนวนสินค้าในตะกร้า """
    cart_item = get_object_or_404(CartItem, id=item_id, cart__user=request.user)

    if action == "increase":
        cart_item.quantity += 1
    elif action == "decrease":
        cart_item.quantity -= 1

    if cart_item.quantity <= 0:
        cart_item.delete()
        return JsonResponse({"success": True, "new_quantity": 0, "new_total": 0, "cart_total": get_cart_total(request.user)})

    cart_item.save()

    return JsonResponse({
        "success": True,
        "new_quantity": cart_item.quantity,
        "new_total": cart_item.total_price(),
        "cart_total": get_cart_total(request.user),
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
        phone = request.POST.get("phone_number")
        city = request.POST.get("city")
        postal_code = request.POST.get("postal_code")

        shipping, created = ShippingAddress.objects.get_or_create(user=request.user)
        shipping.address = address
        shipping.phone_number = phone
        shipping.city = city
        shipping.postal_code = postal_code
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

            order.payment_status = "paid"
            order.save()

        messages.success(request, "✅ ชำระเงินสำเร็จ! กรุณารอการจัดส่ง")
        return redirect('order_history')

    return render(request, "upload_payment.html", {"orders": orders, "total_payment": total_payment})



@login_required
def add_review(request, product_id):
    """ เพิ่มรีวิวสินค้า """
    product = get_object_or_404(Product, id=product_id)

    if request.method == "POST":
        rating = request.POST.get("rating")
        comment = request.POST.get("comment")
        Review.objects.create(user=request.user, product=product, rating=rating, comment=comment)

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

    return render(request, "checkout.html", {
        "orders_by_seller": orders_by_seller,
        "total_checkout_price": total_checkout_price,
        "user_shipping_info": request.user.shipping_address.first(),
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
def cancel_order(request, order_id):
    """ ฟังก์ชันขอยกเลิกออเดอร์ """
    order = get_object_or_404(Order, id=order_id, user=request.user)

    # ตรวจสอบว่าออเดอร์ยังสามารถยกเลิกได้หรือไม่
    if order.status not in ["Pending", "Processing"]:
        messages.error(request, "❌ ไม่สามารถยกเลิกออเดอร์ที่กำลังจัดส่งหรือเสร็จสิ้นแล้ว!")
        return redirect('order_tracking')

    if request.method == "POST":
        reason = request.POST.get("reason", "").strip()
        if not reason:
            messages.error(request, "❌ กรุณากรอกเหตุผลการยกเลิก!")
            return redirect('cancel_order', order_id=order.id)

        order.status = "Cancelled"
        order.cancel_reason = reason
        order.save()

        messages.success(request, "✅ คำขอยกเลิกออเดอร์ของคุณถูกส่งแล้ว!")
        return redirect('order_tracking')

    return render(request, "cancel_order.html", {"order": order})

@login_required
def order_history(request):
    # ดึงคำสั่งซื้อทั้งหมดของผู้ใช้
    orders = Order.objects.filter(user=request.user)

    return render(request, 'order_history.html', {
        'orders': orders
    })




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
    """ ยืนยันคำสั่งซื้อ และบันทึกลงฐานข้อมูล """
    cart = Cart.objects.get(user=request.user)
    cart_items = CartItem.objects.filter(cart=cart)

    if not cart_items:
        messages.error(request, "❌ ไม่มีสินค้าในตะกร้า กรุณาเลือกสินค้าก่อนทำการสั่งซื้อ!")
        return redirect('cart')

    shipping_address = request.POST.get("shipping_address", "").strip()
    phone_number = request.POST.get("phone_number", "").strip()

    if not shipping_address or not phone_number:
        messages.error(request, "❌ กรุณากรอกที่อยู่จัดส่งและเบอร์โทรศัพท์ให้ครบ!")
        return redirect('checkout')

    orders_by_seller = {}
    order_ids = []  # ✅ เก็บหมายเลขออเดอร์

    for item in cart_items:
        seller = item.product.seller
        if seller not in orders_by_seller:
            orders_by_seller[seller] = []
        orders_by_seller[seller].append(item)

    for seller, items in orders_by_seller.items():
        total_price = sum(item.product.price * item.quantity for item in items)

        order = Order.objects.create(
            user=request.user,
            seller=seller,
            shipping_address=shipping_address,
            phone_number=phone_number,
            total_price=total_price,
            status="pending",
        )
        order_ids.append(str(order.id))  # ✅ ต้องแปลงเป็น `str()`

        for item in items:
            OrderItem.objects.create(
                order=order,
                product=item.product,
                seller=item.product.seller,
                quantity=item.quantity,
                price_per_item=item.product.price
            )

    cart_items.delete()  # ✅ ล้างตะกร้าหลังจากสร้างคำสั่งซื้อ

    # ✅ ใช้ `redirect()` ให้ถูกต้อง
    return redirect(f"/payment/upload/{','.join(order_ids)}/")

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
    """ อัปเดตสถานะการจัดส่งคำสั่งซื้อ """
    order = get_object_or_404(Order, id=order_id, seller=request.user.seller_profile)

    if status in ["shipped", "delivered"]:  # ตรวจสอบว่าสถานะที่อัปเดตถูกต้อง
        order.status = status
        order.save()
    
    return redirect("seller_orders")

@login_required
def cancel_order(request, order_id):
    """ ยกเลิกคำสั่งซื้อ """
    order = get_object_or_404(Order, id=order_id, seller=request.user.seller_profile)
    order.status = "canceled"
    order.save()
    
    return redirect("seller_orders")


@login_required
def seller_payment_verification(request):
    """แสดงออเดอร์ของผู้ขายที่มีการชำระเงิน (ทั้ง pending และ paid)"""
    seller = getattr(request.user, 'seller_profile', None)

    if not seller:
        messages.error(request, "คุณไม่ใช่ผู้ขาย ไม่สามารถเข้าถึงหน้านี้ได้")
        return redirect("home")

    # ✅ ดึงออเดอร์ที่เกี่ยวข้องกับผู้ขาย
    orders = Order.objects.filter(
        seller=seller,
        payment_status__in=["pending", "paid"]
    ).select_related('payment')

    # ✅ ดึงข้อมูลการชำระเงินแยกต่างหาก (สำหรับการตรวจสอบ)
    payments = {payment.order.id: payment for payment in Payment.objects.filter(order__seller=seller)}

    return render(request, "payments/seller_payment_verification.html", {
        "orders": orders,
        "payments": payments  # ✅ ส่ง payments dictionary ไปให้ template
    })


@login_required
def approve_seller_payment(request, order_id):
    """ผู้ขายอนุมัติการชำระเงิน"""
    order = get_object_or_404(Order, id=order_id, seller=request.user.seller_profile)

    if not hasattr(order, 'payment'):
        messages.error(request, f"❌ ไม่พบข้อมูลการชำระเงินของออเดอร์ #{order.id}")
        return redirect("seller_payment_verification")

    order.payment_status = "paid"
    order.status = "pending"  # เปลี่ยนเป็นรอการจัดส่ง
    order.save()

    messages.success(request, f"✅ ออเดอร์ #{order.id} ได้รับการอนุมัติแล้ว")
    return redirect("seller_payment_verification")

@login_required
def reject_seller_payment(request, order_id):
    """ผู้ขายปฏิเสธการชำระเงิน"""
    order = get_object_or_404(Order, id=order_id, seller=request.user.seller_profile)

    if not hasattr(order, 'payment'):
        messages.error(request, f"❌ ไม่พบข้อมูลการชำระเงินของออเดอร์ #{order.id}")
        return redirect("seller_payment_verification")

    order.payment_status = "pending"  # กลับไปเป็นรอการชำระเงิน
    order.save()

    messages.warning(request, f"❌ ออเดอร์ #{order.id} ถูกปฏิเสธ")
    return redirect("seller_payment_verification")

from .models import Follow, CustomUser
# ✅ สร้างฟังก์ชันสำหรับการติดตามผู้ใช้
@login_required
def follow_user(request, user_id):
    user_to_follow = get_object_or_404(CustomUser, id=user_id)

    if user_to_follow == request.user:
        return JsonResponse({"success": False, "message": "You cannot follow yourself."}, status=400)

    follow, created = Follow.objects.get_or_create(follower=request.user, following=user_to_follow)

    if not created:
        follow.delete()  # ยกเลิกการติดตามถ้ากดซ้ำ
        return JsonResponse({"success": True, "message": "Unfollowed successfully."})

    return JsonResponse({"success": True, "message": "Followed successfully."})


@login_required
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
    })