from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth import views as auth_views
from django.urls import path
from . import views
from .views import logout_view, login_view, seller_login, seller_logout, register_seller, product_list, add_product, my_products, product_detail, delete_product
from .views import (
    logout_view, login_view, seller_login, seller_logout, register_seller, product_list, 
    add_product, my_products, product_detail, delete_product, delete_post, edit_post, 
    edit_store, edit_group_post, delete_group_post, save_group_post, share_group_post,
    add_to_cart, view_cart, update_cart, remove_from_cart, checkout, update_shipping,
    add_review, order_tracking, return_order, cancel_order, report_post, block_user,
    admin_login, admin_dashboard, delete_reported_post, admin_register,
)


urlpatterns = [
    path('home/', views.home, name='home'),
    path('register/', views.register, name='register'),
    path('login/', login_view, name='login'),  # เส้นทางหน้า Login
    path('logout/', logout_view, name='logout'),
    path('forgotPass/', views.forgotPass, name='forgotPass'),# URL ชื่อ forgotPass
    path('community1/', views.community, name='community'),  # เพิ่มเส้นทาง community
    path('savelist/', views.savelist, name='savelist'),
    path('profile_management/', views.profile_management, name='profile_management'),
    path('follow/<int:user_id>/', views.follow_user, name='follow_user'),
    path('report/<int:post_id>/', report_post, name='report_post'),  # ✅ เพิ่ม URL pattern สำหรับการรายงานโพสต์

    
    path('community/', views.community_list, name='community_list'),
    path('community/create/', views.create_group, name='create_group'),
    path('community/<int:group_id>/', views.group_detail, name='group_detail'),
    path('community/<int:group_id>/join/', views.join_group, name='join_group'),
    #like
    path('create_post/', views.create_post, name='create_post'),
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
    path('edit-seller-profile/', views.edit_seller_profile, name='edit_seller_profile'),

    # ✅ ตะกร้าสินค้า (Shopping Cart)
    path('cart/', view_cart, name='cart'),
    path('cart/add/<int:product_id>/', add_to_cart, name='add_to_cart'),
    path('cart/remove/<int:item_id>/', views.remove_from_cart, name='remove_from_cart'),
    path('cart/update/<int:item_id>/<str:action>/', views.update_cart, name='update_cart'),


    # ✅ การสั่งซื้อ (Checkout & Order)
    path('checkout/', checkout, name='checkout'),
    path('shipping/update/', update_shipping, name='update_shipping'),
    path('order/history/', views.order_history, name='order_history'),
    path('order/track/', order_tracking, name='order_tracking'),

    # ✅ การชำระเงิน (Payment)
    path("payment/upload/<str:order_ids>/", views.upload_payment, name="upload_payment"),


    # ✅ รีวิวสินค้า
    path('review/add/<int:product_id>/', add_review, name='add_review'),

    # ✅ การคืนสินค้า/ยกเลิกออเดอร์
    path('order/return/<int:order_id>/', return_order, name='return_order'),
    path('order/cancel/<int:order_id>/', cancel_order, name='cancel_order'),
    path("checkout/confirm/", views.confirm_order, name="confirm_order"),
    path("order/<int:order_id>/", views.order_detail, name="order_detail"),
    #path('edit-address/', views.edit_shipping_address, name='edit_shipping_address'),
    #path('edit-address/<int:order_id>/', views.edit_shipping_address, name='edit_shipping_address'),
    path("checkout/", checkout, name="checkout"),
    path("checkout/confirm/", views.confirm_order, name="confirm_order"),
    path('order/<int:order_id>/edit/', views.edit_order, name='edit_order'),
    path('order/edit/<int:order_id>/', views.edit_shipping_address, name='edit_shipping_address'),


    path("seller/orders/", views.seller_orders, name="seller_orders"),
    path("seller/orders/<int:order_id>/update/<str:status>/", views.update_order_status, name="update_order_status"),
    path("seller/orders/<int:order_id>/cancel/", views.cancel_order, name="cancel_order"),
    #path("homemain/", views.search_content, name="search_content"),
    path('search/', views.search_content, name='search'),  # ✅ เพิ่มเส้นทางค้นหา
    #path('all-posts/', views.all_posts, name='all_posts'),  # ✅ เพิ่มเส้นทางสำหรับดูโพสต์ทั้งหมด
    path('', views.all_posts, name='all_posts'),

    path("seller/payments/", views.seller_payment_verification, name="seller_payment_verification"),
    path("seller/payments/approve/<int:order_id>/", views.approve_seller_payment, name="approve_seller_payment"),
    path("seller/payments/reject/<int:order_id>/", views.reject_seller_payment, name="reject_seller_payment"),


    # ✅ เส้นทางสำหรับรีเซ็ตรหัสผ่าน
    path('password_reset/', auth_views.PasswordResetView.as_view(template_name='password_reset.html'), name='password_reset'),
    path('password_reset_done/', auth_views.PasswordResetDoneView.as_view(template_name='password_reset_done.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name='password_reset_confirm.html'), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='password_reset_complete.html'), name='password_reset_complete'),
    
    path('block_user/<int:user_id>/', block_user, name='block_user'),  # ✅ เพิ่ม URL pattern สำหรับการบล็อกผู้ใช้

    # ✅ เส้นทางสำหรับการลงชื่อเข้าใช้ของผู้ดูแลระบบ
    path('admin_register/', admin_register, name='admin_register'),  # ✅ เส้นทางสมัครแอดมิน
    path('admin_login/', admin_login, name='admin_login'),
    path('admin_dashboard/', admin_dashboard, name='admin_dashboard'),
    path('delete_post/<int:post_id>/', delete_reported_post, name='delete_reported_post'),
    path('admin_logout/', logout_view, name='admin_logout'),  # ✅ เพิ่มเส้นทางออกจากระบบของแอดมิน

]
