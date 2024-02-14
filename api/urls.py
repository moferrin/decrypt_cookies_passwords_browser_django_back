from django.urls import path

from . import views

urlpatterns = [
    path("get_data_chrome", views.get_data_chrome, name="get_data_chrome"),
    path("get_data_brave", views.get_data_brave, name="get_data_brave")
]