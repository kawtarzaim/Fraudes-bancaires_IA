from django.contrib import admin

from .models import LoginHistory, Payment


@admin.register(LoginHistory)
class LoginHistoryAdmin(admin.ModelAdmin):
    list_display = ('user', 'ip_address', 'country', 'login_time', 'ai_result')
    search_fields = ('user__username', 'ip_address', 'country')


@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display = ('user', 'payment_type', 'amount', 'country', 'payment_date')
    list_filter = ('payment_type', 'country')
    search_fields = ('user__username', 'country')
