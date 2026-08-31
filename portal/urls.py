from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard_view, name='dashboard'),
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    
    # File Management
    path('upload/', views.upload_file_view, name='upload_file'),
    path('download/<uuid:file_id>/', views.download_file_view, name='download_file'),
    path('share/<uuid:file_id>/', views.share_file_view, name='share_file'),
    path('revoke/<int:share_id>/', views.revoke_share_view, name='revoke_share'),
    path('delete/<uuid:file_id>/', views.delete_file_view, name='delete_file'),
    
    # Admin Security Dashboard
    path('admin-portal/', views.admin_dashboard_view, name='admin_dashboard'),
]
