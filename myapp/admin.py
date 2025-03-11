from django.contrib import admin

# Register your models here.
from django.contrib import admin
from .models import Post, Report, BlockedUser

class ReportAdmin(admin.ModelAdmin):
    list_display = ('post', 'reported_by', 'reason', 'created_at')
    list_filter = ('reason', 'created_at')
    search_fields = ('post__content', 'reported_by__username')
    actions = ['mark_post_as_hidden']

    def mark_post_as_hidden(self, request, queryset):
        for report in queryset:
            report.post.is_reported = True
            report.post.save()
        self.message_user(request, "Selected posts have been marked as hidden.")
    mark_post_as_hidden.short_description = "Mark selected reports' posts as hidden"

class PostAdmin(admin.ModelAdmin):
    list_display = ('user', 'content', 'created_at', 'is_reported')
    search_fields = ('user__username', 'content')

class BlockedUserAdmin(admin.ModelAdmin):
    list_display = ('blocked_by', 'blocked_user', 'created_at')

admin.site.register(Post, PostAdmin)
admin.site.register(Report, ReportAdmin)
admin.site.register(BlockedUser, BlockedUserAdmin)


from django.contrib import admin
from .models import WithdrawalRequest

@admin.register(WithdrawalRequest)
class WithdrawalRequestAdmin(admin.ModelAdmin):
    list_display = ("seller", "amount", "status", "created_at")
    list_filter = ("status",)
    search_fields = ("seller__store_name", "amount")

