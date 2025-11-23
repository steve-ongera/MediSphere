from django.contrib import admin
from django.urls import path, include, re_path
from django.conf import settings
from django.conf.urls.static import static
from django.views.static import serve


urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('main_application.urls')),
]

# =========================================================
# STATIC & MEDIA FILES (Development Only)
# =========================================================

# Static files
urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

# Media files using re_path
if settings.DEBUG:
    urlpatterns += [
        re_path(r'^media/(?P<path>.*)$', 
                serve, 
                {'document_root': settings.MEDIA_ROOT}),
    ]

# =========================================================
# CUSTOM ERROR HANDLERS
# =========================================================

handler404 = 'main_application.views.error_404'
handler500 = 'main_application.views.error_500'
handler403 = 'main_application.views.error_403'
handler400 = 'main_application.views.error_400'
