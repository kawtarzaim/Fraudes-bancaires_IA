from django.urls import path

from .views import (
    ai_results_view,
    dashboard_view,
    home_view,
    login_history_view,
    login_view,
    logout_view,
    payments_view,
    register_view,
)

urlpatterns = [
    path('', home_view, name='home'),
    path('login/', login_view, name='login'),
    path('register/', register_view, name='register'),
    path('dashboard/', dashboard_view, name='dashboard'),
    path('payments/', payments_view, name='payments'),
    path('history/', login_history_view, name='login_history'),
    path('ai-results/', ai_results_view, name='ai_results'),
    path('logout/', logout_view, name='logout'),
]
