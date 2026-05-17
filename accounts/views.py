from datetime import timedelta

from django.contrib import messages
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.shortcuts import redirect, render
from django.utils import timezone

from .ai_model import predict_login
from .forms import LoginForm, PaymentForm, RegisterForm
from .models import LoginHistory, Payment
from .utils import get_client_ip, get_country_from_ip


MAX_FAILED_LOGIN_ATTEMPTS = 3
LOGIN_BLOCK_MINUTES = 1


def get_recent_failed_attempts(user, now=None):
    """Count wrong-password attempts since the last success or block event."""
    now = now or timezone.now()
    latest_success = LoginHistory.objects.filter(
        user=user,
        event_type='SUCCESS',
    ).first()
    latest_block = LoginHistory.objects.filter(
        user=user,
        event_type='TEMP_BLOCKED',
        blocked_until__lte=now,
    ).first()

    reset_time = None
    if latest_success:
        reset_time = latest_success.login_time
    if latest_block and (reset_time is None or latest_block.login_time > reset_time):
        reset_time = latest_block.login_time

    failed_logins = LoginHistory.objects.filter(
        user=user,
        event_type='FAILED',
    )
    if reset_time:
        failed_logins = failed_logins.filter(login_time__gt=reset_time)
    return failed_logins.count()


def get_active_login_block(user, now):
    """Return the latest active temporary block for this user, if one exists."""
    return LoginHistory.objects.filter(
        user=user,
        event_type='TEMP_BLOCKED',
        blocked_until__gt=now,
    ).first()


def create_login_alert(
    user,
    ip_address,
    country,
    login_time,
    ai_result,
    failed_attempts,
    event_type,
    blocked_until=None,
):
    """Store every suspicious or blocked login event for audit and alerting."""
    return LoginHistory.objects.create(
        user=user,
        ip_address=ip_address,
        country=country,
        login_time=login_time,
        ai_result=ai_result,
        failed_attempts=failed_attempts,
        event_type=event_type,
        blocked_until=blocked_until,
    )


def home_view(request):
    """Public home page for the AI banking system."""
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'accounts/home.html')


def register_view(request):
    """View for user registration."""
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('login')
    else:
        form = RegisterForm()

    return render(request, 'accounts/register.html', {'form': form})


def login_view(request):
    """
    View for user login with three-layer security:

    LAYER 1: Temporary Block Check
        If user has 3+ failed attempts, block for 1 minute -> TEMP_BLOCKED

    LAYER 2: Credentials Check
        Check username/password -> authenticate()

    LAYER 3: AI Fraud Detection
        Check IP, country, login hour, and failed attempts
        - Normal evening/night logins from home are allowed
        - Foreign country + suspicious IP is suspicious
        - Suspicious IP + failed attempts is suspicious

    LAYER 4: Failed Attempt Tracking
        Track wrong passwords to prevent brute force
        After 3 failed attempts -> block for 1 minute
    """
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            ip_address = get_client_ip(request)
            country = get_country_from_ip(ip_address)
            server_time = timezone.localtime(timezone.now())

            target_user = User.objects.filter(username=username).first()
            if target_user:
                # LAYER 1: Check if account is temporarily blocked (3 failed attempts)
                # This prevents brute force attacks on known usernames
                active_block = get_active_login_block(target_user, server_time)
                if active_block:
                    messages.error(
                        request,
                        'Too many failed attempts. Try again later.',
                    )
                    return redirect('login')

            # LAYER 2: Authenticate with Django
            # This checks if password is correct
            user = authenticate(request, username=username, password=password)
            if user is not None:
                failed_attempts = get_recent_failed_attempts(user, server_time)
                # LAYER 3: AI Fraud Detection
                # The model uses only existing project signals: IP risk,
                # country, server login hour, and recent failed attempts.
                ai_result = predict_login(
                    ip_address,
                    country,
                    server_time.hour,
                    failed_attempts,
                )

                if ai_result == 'Suspicious Login':
                    # AI detected fraud: block login and log alert
                    create_login_alert(
                        user=user,
                        ip_address=ip_address,
                        country=country,
                        login_time=server_time,
                        failed_attempts=failed_attempts,
                        ai_result='Suspicious Login',
                        event_type='AI_BLOCKED',
                    )
                    messages.error(
                        request,
                        'Suspicious login detected by the AI model. Access has been blocked.',
                    )
                    return redirect('login')

                # Login passed all checks: credentials OK + AI approved
                # Record successful login in history
                create_login_alert(
                    user=user,
                    ip_address=ip_address,
                    country=country,
                    login_time=server_time,
                    failed_attempts=0,
                    ai_result='Normal Login',
                    event_type='SUCCESS',
                )
                auth_login(request, user)
                return redirect('dashboard')

            # LAYER 4: Password was wrong - track failed attempt
            # Count failures to block brute force attacks
            if target_user:
                failed_attempts = get_recent_failed_attempts(target_user, server_time) + 1
                blocked_until = None
                event_type = 'FAILED'
                ai_result = 'Normal Login'

                # After 3 failed attempts, block account for 1 minute
                # This prevents attackers from guessing passwords endlessly
                if failed_attempts >= MAX_FAILED_LOGIN_ATTEMPTS:
                    blocked_until = server_time + timedelta(minutes=LOGIN_BLOCK_MINUTES)
                    event_type = 'TEMP_BLOCKED'
                    ai_result = 'Suspicious Login'  # Mark as suspicious in database

                # Record this failed attempt (or block) in history
                create_login_alert(
                    user=target_user,
                    ip_address=ip_address,
                    country=country,
                    login_time=server_time,
                    ai_result=ai_result,
                    failed_attempts=failed_attempts,
                    event_type=event_type,
                    blocked_until=blocked_until,
                )

                # If blocked due to too many attempts, show error
                if blocked_until:
                    messages.error(
                        request,
                        'Too many failed attempts. Try again later.',
                    )
                    return redirect('login')

            # Generic error message for non-existent users or wrong password
            # This is a security best practice: don't reveal which users exist
            messages.error(request, 'Invalid credentials. Please check your username and password.')
            return redirect('login')
    else:
        form = LoginForm()

    return render(request, 'accounts/login.html', {'form': form})


@login_required
def dashboard_view(request):
    """Secure banking dashboard with activity and statistics."""
    total_logins = LoginHistory.objects.filter(
        user=request.user,
        event_type='SUCCESS',
    ).count()
    suspicious_logins = LoginHistory.objects.filter(
        user=request.user,
        event_type__in=['AI_BLOCKED', 'TEMP_BLOCKED'],
    ).count()
    total_payments = Payment.objects.filter(user=request.user).count()
    latest_logins = LoginHistory.objects.filter(user=request.user)[:6]

    return render(
        request,
        'accounts/dashboard.html',
        {
            'total_logins': total_logins,
            'suspicious_logins': suspicious_logins,
            'total_payments': total_payments,
            'latest_logins': latest_logins,
        },
    )


@login_required
def payments_view(request):
    """Payments page with manual transaction records."""
    if request.method == 'POST':
        form = PaymentForm(request.POST)
        if form.is_valid():
            payment = form.save(commit=False)
            payment.user = request.user
            payment.save()
            return redirect('payments')
    else:
        form = PaymentForm()

    payments = Payment.objects.filter(user=request.user)[:10]
    total_payments = payments.count()

    return render(
        request,
        'accounts/payments.html',
        {
            'form': form,
            'payments': payments,
            'total_payments': total_payments,
        },
    )


@login_required
def login_history_view(request):
    """Login history page separate from AI results."""
    histories = LoginHistory.objects.filter(user=request.user)
    return render(request, 'accounts/login_history.html', {'histories': histories})


@login_required
def ai_results_view(request):
    """AI detection results page with login outcome details."""
    histories = LoginHistory.objects.filter(user=request.user)
    total = histories.count()
    suspicious = histories.filter(event_type__in=['AI_BLOCKED', 'TEMP_BLOCKED']).count()
    normal = histories.filter(event_type='SUCCESS').count()

    return render(
        request,
        'accounts/ai_results.html',
        {
            'histories': histories,
            'total': total,
            'suspicious': suspicious,
            'normal': normal,
        },
    )


@login_required
def logout_view(request):
    """Logout the user and return to login page."""
    auth_logout(request)
    return redirect('login')
