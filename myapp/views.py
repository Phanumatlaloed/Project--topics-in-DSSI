from django.shortcuts import render, get_object_or_404, redirect
from django.http import HttpResponse, JsonResponse
from .models import Member, User, Post, Comment
from .models import Post, Member, SavedPost
from django.contrib.auth.hashers import make_password, check_password
from django.contrib import messages
from .forms import MemberForm
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import logout
from django.contrib.auth import update_session_auth_hash
from .forms import AccountEditForm, PasswordChangeForm
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from .models import CommunityGroup, GroupPost, GroupComment, UserProfile
from .forms import CommunityGroupForm, GroupPostForm

#สมัครใช้งาน
@csrf_exempt
@csrf_exempt
def register(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        first_name = request.POST.get("first_name")
        last_name = request.POST.get("last_name")
        gender = request.POST.get("gender")
        date_of_birth = request.POST.get("date_of_birth")

        # ตรวจสอบข้อมูลที่จำเป็น
        if not all([username, password, first_name, last_name, gender, date_of_birth]):
            messages.error(request, "กรุณากรอกข้อมูลให้ครบทุกช่อง")
            return render(request, "register.html")

        # ตรวจสอบว่าชื่อผู้ใช้ซ้ำหรือไม่
        if User.objects.filter(username=username).exists():
            messages.error(request, "ชื่อผู้ใช้นี้ถูกใช้งานแล้ว")
            return render(request, "register.html")

        # สร้าง User
        user = User.objects.create_user(
            username=username,
            password=password,
            first_name=first_name,
            last_name=last_name,
        )

        # สร้าง Member
        Member.objects.create(
            user=user,
            gender=gender,
            date_of_birth=date_of_birth,
        )

        messages.success(request, "สมัครสมาชิกสำเร็จ! กรุณาเข้าสู่ระบบ")
        return redirect("login")

    return render(request, "register.html")

#login
def login_view(request):  # เปลี่ยนชื่อจาก login เป็น login_view
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)  # ใช้ login จาก django.contrib.auth
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
        'posts': Post.objects.all().order_by('-created_at'),       # ตัวอย่างการส่งโพสต์
    })
#logout
def logout_view(request):
    logout(request)  # ลบ session ผู้ใช้
    messages.success(request, "คุณได้ออกจากระบบเรียบร้อยแล้ว")
    return redirect('login')  # รีไดเรกต์ไปยังหน้า login

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
    if request.method == 'POST':
        try:
            user = request.user.profile
        except Member.DoesNotExist:
            return JsonResponse({'success': False, 'message': 'User profile not found'}, status=400)

        content = request.POST.get('content', '')
        image = request.FILES.get('image')
        video = request.FILES.get('video')

        post = Post.objects.create(user=user, content=content, image=image, video=video)
        return JsonResponse({'success': True, 'post_id': post.id}, status=201)

    return JsonResponse({'success': False, 'message': 'Invalid request'}, status=400)


@login_required
def toggle_like(request, post_id):
    post = get_object_or_404(Post, id=post_id)
    try:
        user = request.user.profile
    except Member.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'User profile not found'}, status=400)

    if user in post.likes.all():
        post.likes.remove(user)
        liked = False
    else:
        post.likes.add(user)
        liked = True

    return JsonResponse({'success': True, 'liked': liked, 'like_count': post.likes.count()}, status=200)

@login_required
def savelist(request):
    # ดึงโพสต์ที่ผู้ใช้บันทึกไว้
    saved_posts = SavedPost.objects.filter(user=request.user.profile).select_related('post')
    return render(request, 'savelist.html', {'saved_posts': saved_posts}) 


@login_required
def save_post(request, post_id):
    post = get_object_or_404(Post, id=post_id)
    user = request.user.profile

    saved_post, created = SavedPost.objects.get_or_create(user=user, post=post)

    if not created:
        saved_post.delete()
        messages.success(request, "Post removed from saved!")
    else:
        messages.success(request, "Post saved successfully!")

    # รีไดเรกต์กลับไปยังหน้าเดิม
    return redirect(request.META.get('HTTP_REFERER', '/'))

@login_required
def remove_saved_post(request, post_id):
    """
    ลบโพสต์ที่ถูกบันทึก
    """
    post = get_object_or_404(Post, id=post_id)
    user = request.user.profile

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


@login_required
def profile_management(request):
    profile = request.user.profile  # Access Member model through OneToOneField

    # ฟอร์มสำหรับแก้ไขข้อมูลส่วนตัว
    if request.method == 'POST' and 'update_personal_info' in request.POST:
        personal_info_form = AccountEditForm(request.POST, instance=profile)
        if personal_info_form.is_valid():
            personal_info_form.save()
            return redirect('profile_management')  # Refresh the page
    else:
        personal_info_form = AccountEditForm(instance=profile)

    # ฟอร์มสำหรับเปลี่ยนรหัสผ่าน
    if request.method == 'POST' and 'change_password' in request.POST:
        password_form = PasswordChangeForm(user=request.user, data=request.POST)
        if password_form.is_valid():
            request.user.set_password(password_form.cleaned_data.get('new_password'))
            request.user.save()
            update_session_auth_hash(request, request.user)  # Keep the user logged in
            return redirect('profile_management')  # Refresh the page
    else:
        password_form = PasswordChangeForm(user=request.user)

    context = {
        'personal_info_form': personal_info_form,
        'password_form': password_form,
    }
    return render(request, 'profile_management.html', context)


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
            group.members.add(request.user)  # Add creator as member
            return redirect('community_list')
    else:
        form = CommunityGroupForm()
    return render(request, 'create_group.html', {'form': form})

@login_required
def group_detail(request, group_id):
    group = get_object_or_404(CommunityGroup, id=group_id)
    posts = group.posts.all().order_by('-created_at')

    if request.method == 'POST':
        post_form = GroupPostForm(request.POST, request.FILES)
        if post_form.is_valid():
            post = post_form.save(commit=False)
            post.group = group
            post.user = request.user

            # ลบข้อจำกัดสำหรับรูปภาพและวิดีโอ
            if not post.content and not post.image and not post.video:
                messages.error(request, "You must provide either content, an image, or a video.")
            else:
                post.save()
                messages.success(request, "Your post has been created successfully!")
                return redirect('group_detail', group_id=group.id)
    else:
        post_form = GroupPostForm()

    return render(request, 'group_detail.html', {
        'group': group,
        'posts': posts,
        'post_form': post_form,
    })


@login_required
def join_group(request, group_id):
    group = get_object_or_404(CommunityGroup, id=group_id)
    group.members.add(request.user)
    return redirect('group_detail', group_id=group.id)

@login_required
def toggle_group_post_like(request, post_id):
    """
    Toggle the like status for a group post.
    """
    post = get_object_or_404(GroupPost, id=post_id)
    user = request.user

    if post.likes.filter(id=user.id).exists():
        post.likes.remove(user)  # ลบไลค์
        liked = False
    else:
        post.likes.add(user)  # เพิ่มไลค์
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

def profile_management(request):
    profile = request.user.profile  # Access Member model through OneToOneField

    # ฟอร์มสำหรับแก้ไขข้อมูลส่วนตัว
    if request.method == 'POST' and 'update_personal_info' in request.POST:
        personal_info_form = AccountEditForm(request.POST, request.FILES, instance=profile)  # เพิ่ม request.FILES
        if personal_info_form.is_valid():
            personal_info_form.save()
            messages.success(request, "ข้อมูลโปรไฟล์ของคุณถูกแก้ไขเรียบร้อยแล้ว")
            return redirect('profile_management')  # Refresh the page
    else:
        personal_info_form = AccountEditForm(instance=profile)

    # ฟอร์มสำหรับเปลี่ยนรหัสผ่าน
    if request.method == 'POST' and 'change_password' in request.POST:
        password_form = PasswordChangeForm(user=request.user, data=request.POST)
        if password_form.is_valid():
            request.user.set_password(password_form.cleaned_data.get('new_password'))
            request.user.save()
            messages.success(request, "เปลี่ยนรหัสผ่านเรียบร้อยแล้ว")
            return redirect('profile_management')  # Refresh the page
    else:
        password_form = PasswordChangeForm(user=request.user)

    context = {
        'personal_info_form': personal_info_form,
        'password_form': password_form,
    }
    return render(request, 'profile_management.html', context)

@login_required
def profile_view(request):
    # ดึงข้อมูลของผู้ใช้ที่เข้าสู่ระบบ
    member = request.user.profile  # ใช้ request.user.profile หากมี OneToOneField
    
    # ดึงโพสต์ของผู้ใช้งาน
    posts = Post.objects.filter(user=member).order_by('-created_at')

    context = {
        'posts': posts,
        'member': member,
    }
    return render(request, 'profile.html', context)