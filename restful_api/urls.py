from django.urls import include, path
from django.contrib import admin
from rest_1 import views
from rest_framework import permissions
from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework_simplejwt import views as jwt_views
from rest_framework.authtoken.views import obtain_auth_token

schema_view = get_schema_view(
    openapi.Info(title='API',default_version='v1'),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path('admin/',admin.site.urls),
    path('',include('rest_1.urls')),
    path('api-doc/', schema_view.with_ui('swagger',cache_timeout=0)),
    path('api/token/', jwt_views.TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api-token-auth/', obtain_auth_token, name='api_token_auth'),

]