from django.urls import path
from django.conf.urls import url
from .views import *

urlpatterns = [
    path('all/', Get_users.as_view(),name='Get_All_users'),
    path('user/<int:pk>', User_Crud.as_view(),name='Users_crud'),
    path('adduser/', Add_User.as_view(),name='Add_user'),

]