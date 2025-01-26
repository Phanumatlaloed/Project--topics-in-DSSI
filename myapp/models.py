from django.contrib.auth.models import User
from django.db import models
#from django.core.exceptions import ValidationError

class Member(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)
    gender = models.CharField(max_length=10, choices=[('male', 'Male'), ('female', 'Female'), ('other', 'Other')])
    date_of_birth = models.DateField()

    def __str__(self):
        return self.user.username


class Post(models.Model):
    user = models.ForeignKey(Member, on_delete=models.CASCADE, related_name='posts')
    content = models.TextField(blank=True, null=True)
    image = models.ImageField(upload_to='posts/images/', blank=True, null=True)
    video = models.FileField(upload_to='posts/videos/', blank=True, null=True)
    likes = models.ManyToManyField(Member, related_name='liked_posts', blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.user.username}: {self.content[:20]}"

class SavedPost(models.Model):
    user = models.ForeignKey(Member, on_delete=models.CASCADE, related_name='saved_posts')  # ผู้ที่บันทึกโพสต์
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='saves')  # โพสต์ที่ถูกบันทึก
    saved_at = models.DateTimeField(auto_now_add=True)  # เวลาที่บันทึกโพสต์

    def __str__(self):
        return f"{self.user.user.username} saved Post {self.post.id}"


class Comment(models.Model):
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='comments')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} on {self.post.id}: {self.content[:20]}"
    
class CommunityGroup(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField()
    rules = models.TextField()
    image = models.ImageField(upload_to='groups/images/', blank=True, null=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_groups')
    members = models.ManyToManyField(User, related_name='joined_groups', blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class GroupPost(models.Model):
    group = models.ForeignKey(CommunityGroup, on_delete=models.CASCADE, related_name='posts')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.TextField(blank=True, null=True)
    image = models.ImageField(upload_to='groups/posts/', blank=True, null=True)
    video = models.FileField(upload_to='groups/videos/', blank=True, null=True)
    likes = models.ManyToManyField(User, related_name='liked_group_posts', blank=True)  # เพิ่ม field likes
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.group.name}"

    
class GroupComment(models.Model):
    post = models.ForeignKey(GroupPost, on_delete=models.CASCADE, related_name='comments')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} on {self.post.id}: {self.content[:20]}"
    
class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)

    def __str__(self):
        return self.user.username