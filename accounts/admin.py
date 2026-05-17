from django.contrib import admin

from .models import LoginHistory, Payment


@admin.register(LoginHistory)
class LoginHistoryAdmin(admin.ModelAdmin):
    list_display = (
        'user',
        'ip_address',
        'country',
        'login_time',
        'ai_result',
        'event_type',
        'failed_attempts',
        'blocked_until',
    )
    list_filter = ('ai_result', 'event_type', 'country')
    search_fields = ('user__username', 'ip_address', 'country')


@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display = ('user', 'payment_type', 'amount', 'country', 'payment_date')
    list_filter = ('payment_type', 'country')
    search_fields = ('user__username', 'country')
