from django.conf.urls import url
from django.urls import path, include
from django.views.generic import TemplateView
from django.views.static import serve

import xadmin
from rest_framework.documentation import include_docs_urls
from rest_framework.schemas import get_schema_view
from rest_framework import routers
from rest_framework.authtoken import views
from rest_framework_jwt.views import obtain_jwt_token

from bwShop.settings import MEDIA_ROOT
from goods.views import GoodsListViewSet, CategoryViewSet, BannerViewset, IndexCategoryViewset
from users.views import SmsCodeViewset,UserViewset
from user_operation.views import UserFavViewset, LeavingMessageViewset, AddressViewset
from trade.views import ShoppingCartViewset, OrderViewset, AlipayView

router = routers.DefaultRouter()
router.register('goods',GoodsListViewSet)
router.register('categorys',CategoryViewSet,basename='categorys')
router.register('code',SmsCodeViewset,basename='code')
router.register('users',UserViewset,basename="users")
router.register('userfavs',UserFavViewset,basename='userfavs')
router.register('messages',LeavingMessageViewset,basename='messages')
router.register('address',AddressViewset , basename="address")
router.register('shopcarts',ShoppingCartViewset,basename='shopcarts')
router.register('orders',OrderViewset,basename='orders')
router.register('banners',BannerViewset,basename='banners')
router.register('indexgoods',IndexCategoryViewset,basename='indexgoods')


schema_view = get_schema_view(title='corejson')

urlpatterns = [
    path('xadmin/',xadmin.site.urls),
    path('ueditor/',include('DjangoUeditor.urls')),
    # 文件上传路径
    path('media/<path:path>',serve,{'document_root':MEDIA_ROOT}),
    # path('goods/',GoodsListViewSet.as_view(),name='goods-list'),
    # 商品列表页
    path('', include(router.urls)),
    path('api-token-auth/',views.obtain_auth_token),
    # jwt认证登录
    path('login/', obtain_jwt_token ),
    path('api-auth/',include('rest_framework.urls')),
    path('docs/',include_docs_urls(title='生鲜项目的文档')),
    path('schema/',schema_view),
    # 首页
    path('index/', TemplateView.as_view(template_name='index.html'),name='index'),
    path('alipay/return/',AlipayView.as_view()),
    path('',include('social_django.urls',namespace='social'))
]