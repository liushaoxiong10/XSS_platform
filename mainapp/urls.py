from django.urls import path
from .views import *

urlpatterns = [

   path('',Index_view.as_view(),name="index"),
   path('pages/dynamic', DynamicTest_view.as_view(), name="dynamic"),
   path('pages/static', StaticTest_view.as_view(), name="static"),
   path('pages/history', History_view.as_view(), name="history"),
   path("pages/getreport", GetReport_view.as_view(), name="get_report"),
]