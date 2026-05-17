from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.shortcuts import redirect, render
from django.utils import timezone

from .ai_model import predict_login
from .forms import LoginForm, PaymentForm, RegisterForm
from .models import LoginHistory, Payment
from .utils import get_client_ip, get_country_from_ip


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
    """View for user login and AI fraud check."""
    message = ''
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)
            if user is not None:
                auth_login(request, user)

                # hna kanjibo l IP dyal user
                ip_address = get_client_ip(request)
                # hna kanjibo country mn IP
                country = get_country_from_ip(ip_address)
                # hna kanst3mlo server time bash n7ddo lwa9t dyal login
                # Server time is more secure and harder to manipulate than user local time.
                # waqt server akthar aman w ma yt7akkamsh fih user b easily.
                server_time = timezone.localtime(timezone.now())
                ai_result = predict_login(ip_address, country, server_time.hour)

                LoginHistory.objects.create(
                    user=user,
                    ip_address=ip_address,
                    country=country,
                    login_time=server_time,
                    ai_result=ai_result,
                )

                return redirect('dashboard')
            message = 'Invalid credentials. Please check your username and password.'
    else:
        form = LoginForm()

    return render(request, 'accounts/login.html', {'form': form, 'message': message})


@login_required
def dashboard_view(request):
    """Secure banking dashboard with activity and statistics."""
    total_logins = LoginHistory.objects.filter(user=request.user).count()
    suspicious_logins = LoginHistory.objects.filter(
        user=request.user, ai_result='Suspicious Login'
    ).count()
    total_payments = Payment.objects.filter(user=request.user).count()
    total_users = User.objects.count()
    latest_logins = LoginHistory.objects.filter(user=request.user)[:6]

    return render(
        request,
        'accounts/dashboard.html',
        {
            'total_logins': total_logins,
            'suspicious_logins': suspicious_logins,
            'total_payments': total_payments,
            'total_users': total_users,
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
    suspicious = histories.filter(ai_result='Suspicious Login').count()
    normal = histories.filter(ai_result='Normal Login').count()

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
