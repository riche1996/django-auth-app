from django.urls import path
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
from . import views

# Security decorators applied at URL level for defense in depth
# Note: Views should also have their own decorators as primary protection
urlpatterns = [
    path('', views.home, name='home'),
    path('login/', views.login_view, name='login'),
    path('signup/', views.signup_view, name='signup'),
    path('logout/', views.logout_view, name='logout'),
    path('about/', views.about, name='about'),
    
    # Protected endpoints with proper decorator ordering: csrf -> http_methods -> auth -> view
    path('profile/', 
         csrf_protect(login_required(views.profile_view, login_url='/login/')), 
         name='profile'),
    
    path('api/user/<int:user_id>/', 
         csrf_protect(require_http_methods(["GET", "POST"])(login_required(views.user_api, login_url='/login/'))), 
         name='user_api'),
    
    path('search/', 
         csrf_protect(require_http_methods(["GET", "POST"])(login_required(views.search_users, login_url='/login/'))), 
         name='search_users'),
    
    path('delete-account/', 
         csrf_protect(require_http_methods(["POST"])(login_required(views.delete_account, login_url='/login/'))), 
         name='delete_account'),
    
    path('change-password/', 
         csrf_protect(require_http_methods(["POST"])(login_required(views.change_password, login_url='/login/'))), 
         name='change_password'),
    
    # CRITICAL: Export endpoint requires staff privileges
    path('export/', 
         csrf_protect(require_http_methods(["GET"])(staff_member_required(views.export_data))), 
         name='export_data'),
    
    path('update-email/<int:user_id>/', 
         csrf_protect(require_http_methods(["POST"])(login_required(views.update_email, login_url='/login/'))), 
         name='update_email'),
]