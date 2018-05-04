"""tmd URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url
from django.contrib import admin

from apps.hello import views as hello_view
from apps.login import views as login_view
from apps.rule import views as rule_view
from apps.traffic import views as traffic_view

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^api/v1/ping$', hello_view.ping),
    # login and logout
    url(r'^api/v1/login$', login_view.login),
    url(r'^api/v1/logout$', login_view.logout),
    # traffic
    url(r'^api/v1/normal_traffic', traffic_view.show_normal_traffic),
    url(r'^api/v1/mal_traffic', traffic_view.show_mal_traffic),
    # rule
    url(r'^api/v1/list_custom_rule', rule_view.list_custom_rule),
    url(r'^api/v1/add_custom_rule', rule_view.add_custom_rule),
    url(r'^api/v1/delete_custom_rule', rule_view.delete_custom_rule),
    url(r'^api/v1/operate_custom_rule', rule_view.operate_custom_rule),
    url(r'^api/v1/list_static_rule', rule_view.list_static_rule)
]
