from django.contrib.auth.models import User
from django.db import models


class LoginHistory(models.Model):
    EVENT_TYPES = [
        ('SUCCESS', 'Successful login'),
        ('AI_BLOCKED', 'AI blocked login'),
        ('FAILED', 'Failed login'),
        ('TEMP_BLOCKED', 'Temporary blocked login'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    ip_address = models.CharField(max_length=45)
    country = models.CharField(max_length=100, default='Unknown')
    login_time = models.DateTimeField()
    failed_attempts = models.PositiveIntegerField(default=0)
    event_type = models.CharField(
        max_length=20,
        choices=EVENT_TYPES,
        default='SUCCESS',
    )
    blocked_until = models.DateTimeField(null=True, blank=True)
    ai_result = models.CharField(
        max_length=20,
        choices=[
            ('Normal Login', 'Normal Login'),
            ('Suspicious Login', 'Suspicious Login'),
        ],
        default='Normal Login',
    )

    class Meta:
        ordering = ['-login_time']

    def __str__(self):
        return f"{self.user.username} - {self.ai_result} - {self.login_time}"


class Payment(models.Model):
    PAYMENT_TYPES = [
        ('Transfer', 'Transfer'),
        ('Withdrawal', 'Withdrawal'),
        ('Deposit', 'Deposit'),
        ('Card Payment', 'Card Payment'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_type = models.CharField(max_length=30, choices=PAYMENT_TYPES)
    country = models.CharField(max_length=100)
    payment_date = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-payment_date']

    def __str__(self):
        return f"{self.user.username} - {self.payment_type} - {self.amount}"
