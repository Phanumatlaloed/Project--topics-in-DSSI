from django.urls import path
from .views import get_notifications, notifications_list, mark_notification_as_read , all_notifications

urlpatterns = [
    path('', notifications_list, name='notification_list'),
    path('get/', get_notifications, name='get_notifications'),
    path('list/', notifications_list, name='notifications_list'),
    path('', get_notifications, name='get_notifications'),
    path('read/<int:notification_id>/', mark_notification_as_read, name='mark_notification_as_read'),
    path("notifications/", all_notifications, name="notifications"),

]