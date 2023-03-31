from django.urls import path
from . import views
from django.views.decorators.csrf import csrf_exempt
urlpatterns =[
    path('signup/', views.signup_user, name='signup_user'),
    path('login/',views.login_user, name='login_user'),
    path('confirm_user/', views.confirm_user, name='confirm_user'),
    path('reset_pwd/', views.reset_pwd, name='reset_pwd'),
    path('token_gen/', views.gen_token, name='gen_token'),
    path('get_profile/', views.get_profile, name="get_profile"),
    path('update_profile/', views.update_profile, name="update_profile"),
    path('change_password/', views.change_password, name="change_pwd"),
    path('otp_generation/', views.otp_generation, name="otp_gen"),
    path('verify_otp/', views.verify_otp, name="verify_otp"),
    path('image_upload/', views.ImageView.as_view(), name="image_upload"),
    path('get_customer_id/', views.get_customer_id, name='get_customer_id'),
    path('new_house/', views.submit_new_house, name='new_house'),
    path('get_house_list/', views.get_house_list, name='get_house_list'),
    path('no_of_visits/', views.create_visit, name='no_of_visits'),
    path('get_visits/', views.get_visits, name='get_visits'),
    path('create_template/', views.create_template, name="create_template"),
    path('create_report/', views.create_report, name='create_report'),
    path('get_reports_list/', views.get_reports_list, name='get_reports_list'),
    path('visit_details/', views.visit_details, name='visit_details/'),
    path('check_report_status/', views.check_report_status, name='check_report_status/'),
    path('TES_superadmin_login/', views.TES_superadmin_login, name='TES_superadmin_login/'),
    path('get_all_users/', views.get_all_users, name='get_all_users/'),
    path('get_all_houses/', views.get_all_houses, name='get_all_houses/'),
    path('get_all_visits/', views.get_all_visits, name='get_all_visits/'),
    path('get_all_reports/', views.get_all_reports, name='get_all_reports/'),
    path('get_all_templates/', views.get_all_templates, name='get_all_templates/'),
    path('delete_user/', views.delete_user, name='delete_user/'),
    path('delete_house/', views.delete_house, name='delete_house/'),
    path('delete_visit/', views.delete_visit, name='delete_visit/'),
    path('delete_report/', views.delete_report, name='delete_report/'),
    path('delete_template/', views.delete_template, name='delete_template/'),
    path('edit_user/', views.edit_user, name='edit_user/'),
    path('edit_house/', views.edit_house, name='edit_house/'),
    path('edit_report/', views.edit_report, name='edit_report/'),
    path('edit_visit/', views.edit_visit, name='edit_visit/'),
    path('edit_template/', views.edit_template, name='edit_template/'),
    path('HousesViewSet/', views.HousesViewSet.as_view({"get":"list"}) , name='HousesViewSet/'),
    path('HousesViewSet2/', views.HousesViewSet2.as_view({"get":"list"}) , name='HousesViewSet/'),
    path('pws/', views.PWS, name='PWS/')
    ]