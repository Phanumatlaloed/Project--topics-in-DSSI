from django.conf import settings
from django.conf.urls.static import static
from django.urls import path
from . import views
from .views import logout_view, login_view, seller_login, seller_logout, register_seller, product_list, add_product, my_products, product_detail, delete_product
from .views import delete_post, edit_post,edit_store
from .views import (
    edit_group_post, delete_group_post,
   save_group_post, share_group_post
)

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

    path('post/<int:post_id>/delete/', views.delete_post, name='delete_post'),
    path('post/<int:post_id>/edit/', views.edit_post, name='edit_post'),
    path('post/<int:post_id>/', views.post_detail, name='post_detail'),  # ✅ แก้ปัญหา NoReverseMatch
    path('delete_media/<int:media_id>/', views.delete_media, name='delete_media'),


    path('post/<int:post_id>/share/', views.share_post, name='share_post'),
    path('community/<int:group_id>/edit/', views.edit_group, name='edit_group'),
    path('community/<int:group_id>/delete/', views.delete_group, name='delete_group'),


    path('group_post/<int:post_id>/edit/', edit_group_post, name='edit_group_post'),
    path('group/post/<int:post_id>/delete/', delete_group_post, name='delete_group_post'),
    path('group/post/<int:post_id>/save/', save_group_post, name='save_group_post'),
    path('group/post/<int:post_id>/share/', share_group_post, name='share_group_post'),


    path("seller/login/", seller_login, name="seller_login"),
    path("seller/logout/", seller_logout, name="seller_logout"),
    path("seller/register/", register_seller, name="register_seller"),
    path("dashboard/", views.seller_dashboard, name="seller_dashboard"),
    path("product/add/", views.add_product, name="add_product"),
    path("product/<int:product_id>/edit/", views.edit_product, name="edit_product"),
    path("product/<int:product_id>/delete/", views.delete_product, name="delete_product"),

    path("products/", product_list, name="product_list"),
    path("products/my/", my_products, name="my_products"),
    path("products/add/", add_product, name="add_product"),
    path("products/<int:product_id>/", product_detail, name="product_detail"),
    path('seller/edit/', edit_store, name='edit_store'),
]
