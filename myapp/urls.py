from django.urls import path
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth.decorators import login_required
from . import views

# Wrap sensitive views with security decorators at URL level as additional protection
# Ensure consistent decorator ordering: csrf_protect -> require_http_methods -> login_required -> view
delete_account_secure = csrf_protect(require_http_methods(["POST"])(login_required(views.delete_account)))
user_api_secure = csrf_protect(require_http_methods(["GET", "POST"])(login_required(views.user_api)))
update_email_secure = csrf_protect(require_http_methods(["POST"])(login_required(views.update_email)))
export_data_secure = csrf_protect(require_http_methods(["GET"])(login_required(views.export_data)))
profile_secure = csrf_protect(login_required(views.profile_view))
change_password_secure = csrf_protect(require_http_methods(["POST"])(login_required(views.change_password)))
search_users_secure = csrf_protect(require_http_methods(["GET", "POST"])(login_required(views.search_users)))

urlpatterns = [
    path('', views.home, name='home'),
    path('login/', views.login_view, name='login'),
    path('signup/', views.signup_view, name='signup'),
    path('logout/', views.logout_view, name='logout'),
    path('profile/', profile_secure, name='profile'),
    path('about/', views.about, name='about'),
    # FIXED: Added consistent security decorators across all sensitive endpoints
    path('api/user/<int:user_id>/', user_api_secure, name='user_api'),
    path('search/', search_users_secure, name='search_users'),
    path('delete-account/', delete_account_secure, name='delete_account'),
    path('change-password/', change_password_secure, name='change_password'),
    path('export/', export_data_secure, name='export_data'),
    path('update-email/<int:user_id>/', update_email_secure, name='update_email'),
]