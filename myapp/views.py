from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse
from django.contrib.auth import get_user_model
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.utils import timezone
import os
from .models import Member, Post, Comment, CommunityGroup,PostMedia, GroupPost, Seller, Product, SavedPost, SavedGroupPost, GroupComment
from .forms import CustomUserCreationForm, SellerForm, AccountEditForm, UserEditForm, CustomUserForm, PasswordChangeForm, CommunityGroupForm, GroupPostForm, ProductForm, SellerForm, SellerUpdateForm, UserCreationForm

User = get_user_model()  # ✅ ใช้ CustomUser แทน auth.User


class CustomUserCreationForm(UserCreationForm):
    """ ใช้ CustomUser ในฟอร์ม """
    class Meta:
        model = User  # ✅ ใช้ CustomUser แทน User ปกติ
        fields = ['username','email', 'password1', 'password2']

#สมัครใช้งาน
def register(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        first_name = request.POST.get("first_name")
        last_name = request.POST.get("last_name")
        gender = request.POST.get("gender")
        date_of_birth = request.POST.get("date_of_birth")

        if not all([username, password, first_name, last_name, gender, date_of_birth]):
            messages.error(request, "กรุณากรอกข้อมูลให้ครบทุกช่อง")
            return render(request, "register.html")

        if User.objects.filter(username=username).exists():
            messages.error(request, "ชื่อผู้ใช้นี้ถูกใช้งานแล้ว")
            return render(request, "register.html")

        user = User.objects.create_user(
            username=username,
            password=password,
            first_name=first_name,
            last_name=last_name,
            role='member'  # ✅ กำหนดให้สมัครเป็นสมาชิกโดยดีฟอลต์
        )

        Member.objects.create(user=user, gender=gender, date_of_birth=date_of_birth)
        messages.success(request, "สมัครสมาชิกสำเร็จ! กรุณาเข้าสู่ระบบ")
        return redirect("login")

    return render(request, "register.html")

#login
# ✅ ฟังก์ชันล็อกอิน
def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('home')
        else:
            messages.error(request, 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง')

    return render(request, 'login.html')

#home
#@login_required
#def home(request):
 #   return render(request, 'home.html', {'user': request.user})

@login_required
def home(request):
    return render(request, 'home.html', {
        'username': request.user.username,  # ส่งชื่อผู้ใช้ไปยัง template
        'posts': Post.objects.all().order_by('-created_at')
               # ตัวอย่างการส่งโพสต์
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
    """ ฟังก์ชันลบโพสต์และไฟล์ที่แนบมากับโพสต์ """
    post = get_object_or_404(Post, id=post_id)

    # ✅ ตรวจสอบว่าเป็นเจ้าของโพสต์หรือไม่
    if post.user != request.user:
        return JsonResponse({"success": False, "message": "คุณไม่มีสิทธิ์ลบโพสต์นี้"}, status=403)

    # ✅ ลบไฟล์แนบทั้งหมด
    for media in post.media.all():
        file_path = os.path.join(settings.MEDIA_ROOT, str(media.file))
        if os.path.exists(file_path):
            os.remove(file_path)  # ลบไฟล์ออกจากเซิร์ฟเวอร์

        media.delete()  # ลบจากฐานข้อมูล

    post.delete()  # ลบโพสต์

    return JsonResponse({"success": True, "message": "โพสต์ถูกลบเรียบร้อยแล้ว!"}, status=200)


@login_required
def edit_post(request, post_id):
    """ ฟังก์ชันแก้ไขโพสต์ """
    post = get_object_or_404(Post, id=post_id)

    # ✅ ตรวจสอบว่าเป็นเจ้าของโพสต์หรือไม่
    if post.user != request.user:
        return JsonResponse({"success": False, "message": "คุณไม่มีสิทธิ์แก้ไขโพสต์นี้"}, status=403)

    if request.method == "POST":
        content = request.POST.get("content", "").strip()
        images = request.FILES.getlist("images")
        videos = request.FILES.getlist("videos")

        if not content and not images and not videos and not post.media.exists():
            return JsonResponse({"success": False, "message": "โพสต์ต้องมีข้อความ หรือไฟล์สื่อ"}, status=400)

        # ✅ อัปเดตเนื้อหาโพสต์
        post.content = content
        post.save()

        # ✅ เพิ่มไฟล์ใหม่
        for img in images:
            PostMedia.objects.create(post=post, file=img, media_type='image')

        for vid in videos:
            PostMedia.objects.create(post=post, file=vid, media_type='video')

        return JsonResponse({"success": True, "message": "โพสต์อัปเดตเรียบร้อยแล้ว!", "post_id": post.id})

    return render(request, "edit_post.html", {"post": post})


@login_required
def delete_post(request, post_id):
    """ ฟังก์ชันลบโพสต์ """
    post = get_object_or_404(Post, id=post_id)

    if post.user != request.user:
        return JsonResponse({"success": False, "message": "คุณไม่มีสิทธิ์ลบโพสต์นี้"}, status=403)

    post.delete()
    return JsonResponse({"success": True, "message": "โพสต์ถูกลบเรียบร้อยแล้ว!"})


@login_required
def delete_media(request, media_id):
    """ ฟังก์ชันลบไฟล์สื่อออกจากโพสต์ """
    if request.method == "DELETE":
        media = get_object_or_404(PostMedia, id=media_id)

        # ✅ ตรวจสอบว่าเป็นเจ้าของโพสต์หรือไม่
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
    """ แสดงรายการโพสต์ที่บันทึกไว้ """
    saved_posts = SavedPost.objects.filter(user=request.user.member_profile).select_related('post')
    return render(request, 'savelist.html', {'saved_posts': saved_posts})


@login_required
def save_post(request, post_id):
    post = get_object_or_404(Post, id=post_id)
    user = request.user.member_profile  # ✅ ใช้ member_profile แทน profile

    saved_post, created = SavedPost.objects.get_or_create(user=user, post=post)

    if not created:
        saved_post.delete()
        messages.success(request, "Post removed from saved!")
    else:
        messages.success(request, "Post saved successfully!")

    return redirect(request.META.get('HTTP_REFERER', '/'))

@login_required
def remove_saved_post(request, post_id):
    post = get_object_or_404(Post, id=post_id)
    user = request.user.member_profile  # ✅ ใช้ member_profile แทน profile

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
            Comment.objects.create(post=post, user=request.user, content=content)
            return JsonResponse({'success': True, 'message': 'Comment added successfully!'}, status=201)
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
    groups = CommunityGroup.objects.all()
    return render(request, 'community_list.html', {'groups': groups})

@login_required
def create_group(request):
    if request.method == 'POST':
        form = CommunityGroupForm(request.POST, request.FILES)
        if form.is_valid():
            group = form.save(commit=False)
            group.created_by = request.user
            group.save()
            group.members.add(request.user)  # ✅ ให้ผู้สร้างเป็นสมาชิกกลุ่มอัตโนมัติ
            messages.success(request, "Group created successfully!")
            return redirect('community_list')
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
    user = request.user  # ✅ ใช้ CustomUser โดยตรง
    try:
        member = Member.objects.get(user=user)  # ✅ ดึง Member Profile ให้แน่ใจว่าเป็น CustomUser
    except Member.DoesNotExist:
        member = None  # ✅ ป้องกันกรณีไม่มีโปรไฟล์
    
    posts = Post.objects.filter(user=user).order_by('-created_at')  # ✅ ใช้ user (CustomUser) โดยตรง

    context = {
        'posts': posts,
        'member': member,
        'user': user,  # ✅ ส่ง CustomUser ไปยัง Template
    }
    return render(request, 'profile.html', context)


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


@login_required
def edit_group_post(request, post_id):
    post = get_object_or_404(GroupPost, id=post_id, user=request.user)  # ✅ ใช้ user ไม่ใช่ profile

    if request.method == 'POST':
        post.content = request.POST.get('content', post.content)
        post.image = request.FILES.get('image', post.image)
        post.video = request.FILES.get('video', post.video)
        post.save()
        messages.success(request, 'Group post updated successfully!')
        return redirect('group_detail', group_id=post.group.id)

    return render(request, 'edit_post.html', {'post': post})


@login_required
def delete_group_post(request, post_id):
    if request.method == "POST":
        post = get_object_or_404(GroupPost, id=post_id, user=request.user)  # ✅ แก้จาก profile เป็น user โดยตรง
        post.delete()
        return JsonResponse({"success": True, "message": "Post deleted successfully!"})
    return JsonResponse({"success": False, "message": "Invalid request"}, status=400)


import json

@login_required
def save_group_post(request, post_id):
    if request.method == "POST":
        print("Received Data:", json.loads(request.body))  # ✅ ตรวจสอบข้อมูลที่ส่งมา





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

        if user_form.is_valid() and seller_form.is_valid():
            # ✅ สร้าง User
            user = user_form.save(commit=False)
            user.role = 'seller'
            user.save()

            # ✅ ระบุ Authentication Backend
            user.backend = settings.AUTHENTICATION_BACKENDS[0]  # กำหนด backend ที่ใช้
            
            # ✅ สร้าง Seller Profile
            seller = seller_form.save(commit=False)
            seller.user = user
            seller.email = user.email
            seller.save()

            # ✅ ล็อกอินอัตโนมัติ
            login(request, user)
            messages.success(request, "สมัครเป็นผู้ขายสำเร็จ! 🎉")
            return redirect("seller_dashboard")

    else:
        user_form = CustomUserCreationForm()
        seller_form = SellerForm()

    return render(request, "register_seller.html", {
        "user_form": user_form,
        "seller_form": seller_form
    })



# ✅ แสดงสินค้าทั้งหมด (สำหรับลูกค้าและผู้ขาย)
def product_list(request):
    products = Product.objects.all().order_by("-created_at")
    return render(request, "product_list.html", {"products": products})

# ✅ แสดงสินค้าของร้านค้าตนเอง (เฉพาะผู้ขาย)
@login_required
def my_products(request):
    seller = get_object_or_404(Seller, user=request.user)
    products = seller.products.all()
    return render(request, "my_products.html", {"products": products, "seller": seller})

# ✅ เพิ่มสินค้าใหม่
@login_required
def add_product(request):
    seller = get_object_or_404(Seller, user=request.user)

    if request.method == "POST":
        form = ProductForm(request.POST, request.FILES)
        if form.is_valid():
            product = form.save(commit=False)
            product.seller = seller
            product.save()
            messages.success(request, "เพิ่มสินค้าสำเร็จ!")
            return redirect("my_products")
    else:
        form = ProductForm()

    return render(request, "add_product.html", {"form": form})

# ✅ ดูรายละเอียดสินค้า
def product_detail(request, product_id):
    product = get_object_or_404(Product, id=product_id)
    return render(request, "product_detail.html", {"product": product})

# ✅ ลบสินค้า
@login_required
def delete_product(request, product_id):
    product = get_object_or_404(Product, id=product_id, seller__user=request.user)
    product.delete()
    messages.success(request, "ลบสินค้าเรียบร้อยแล้ว")
    return redirect("my_products")

@login_required
def edit_store(request):
    seller = get_object_or_404(Seller, user=request.user)

    if request.method == 'POST':
        form = SellerUpdateForm(request.POST, request.FILES, instance=seller)
        if form.is_valid():
            form.save()
            messages.success(request, "ข้อมูลร้านค้าอัปเดตเรียบร้อยแล้ว! 🎉")
            return redirect('seller_dashboard')  # ✅ รีไดเรกต์กลับไปยังแดชบอร์ดของร้านค้า
    else:
        form = SellerUpdateForm(instance=seller)

    return render(request, 'edit_store.html', {'form': form, 'seller': seller})

