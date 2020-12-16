from django.urls import path
from hub.views.admin.category import CategoryView
from hub.views.admin.repository import RepositoryView
from hub.views.admin.initialize import InitView
from hub.views.admin.token import TokenView
from hub.views.admin.admin import AdminView, AdminMainView
from hub.views.public.exporters import MainView
from hub.views.public.exporter_detail import DetailView


urlpatterns = [
    path('', MainView.as_view()),
    path('init_done', InitView.as_view()),
    path('token', TokenView.as_view()),
    path('categories', CategoryView.as_view()),
    path('exporter', RepositoryView.as_view()),
    path('exporters/<int:exporter_id>', DetailView.as_view()),
    path('admin', AdminView.as_view()),
    path('admin/exporters', AdminMainView.as_view()),
]
