from django.urls import path,include
import xadmin

urlpatterns = [
    path('xadmin/',xadmin.site.urls),
    path('ueditor/',include('DjangoUeditor.urls'))
]