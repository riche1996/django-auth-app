from django.urls import path
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth.decorators import login_required
from . import views

# Wrap sensitive views with security decorators at URL level as additional protection
delete_account_secure = csrf_protect(require_http_methods(["POST"])(login_required(views.delete_account)))
user_api_secure = login_required(views.user_api)
update_email_secure = csrf_protect(require_http_methods(["POST"])(login_required(views.update_email)))
export_data_secure = login_required(views.export_data)

urlpatterns = [
    path('', views.home, name='home'),
    path('login/', views.login_view, name='login'),
    path('signup/', views.signup_view, name='signup'),
    path('logout/', views.logout_view, name='logout'),
    path('profile/', views.profile_view, name='profile'),
    path('about/', views.about, name='about'),
    # FIXED: Added security decorators at URL level for defense in depth
    path('api/user/<int:user_id>/', user_api_secure, name='user_api'),
    path('search/', views.search_users, name='search_users'),
    path('delete-account/', delete_account_secure, name='delete_account'),
    path('change-password/', views.change_password, name='change_password'),
    path('export/', export_data_secure, name='export_data'),
    path('update-email/<int:user_id>/', update_email_secure, name='update_email'),
]