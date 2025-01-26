from django.conf import settings
from django.conf.urls.static import static
from django.urls import path
from . import views
from .views import register, home, profile_edit
from .views import logout_view, login_view

urlpatterns = [
    path('', views.home, name='home'),
    path('register/', views.register, name='register'),
    path('login/', login_view, name='login'),  # เส้นทางหน้า Login
    path('logout/', logout_view, name='logout'),
    path('forgotPass/', views.forgotPass, name='forgotPass'),# URL ชื่อ forgotPass
    path('community1/', views.community, name='community'),  # เพิ่มเส้นทาง community
    path('savelist/', views.savelist, name='savelist'),
    path('profile_management/', views.profile_management, name='profile_management'),
    
    path('community/', views.community_list, name='community_list'),
    path('community/create/', views.create_group, name='create_group'),
    path('community/<int:group_id>/', views.group_detail, name='group_detail'),
    path('community/<int:group_id>/join/', views.join_group, name='join_group'),
    #like
    path('create/', views.create_post, name='create_post'),
    path('like/<int:post_id>/', views.toggle_like, name='toggle_like'),
    path('save/<int:post_id>/', views.save_post, name='save_post'),
    path('remove_saved_post/<int:post_id>/', views.remove_saved_post, name='remove_saved_post'),
    path('add_comment/<int:post_id>/', views.add_comment, name='add_comment'),

    path('group_post/like/<int:post_id>/', views.toggle_group_post_like, name='toggle_group_post_like'),
    path('group_post/comment/<int:post_id>/', views.add_group_post_comment, name='add_group_post_comment'),

        # Profile management and view
    path('profile/settings/', views.profile_management, name='profile_management'),  # เส้นทางตั้งค่าโปรไฟล์
    path('profile/', views.profile_view, name='profile'),  # เส้นทางแสดงโปรไฟล์

]
