from django.contrib import admin
from .models import TES_new_Model, TES_otp_model, TES_file_upload_model, TES_submit_new_house_model, TES_house_visits_model, TES_template_model, TES_report_model, TES_superadmin
class TES_admin(admin.ModelAdmin):
    readonly_fields=('id',)
# class TES_house_visits_admin(admin.ModelAdmin):
    # list = ('current_status', ) 
    # list_display_links = ('current_status', ) 
    # list_display = ('current_status', )
    # list_select_related = ('current_status', )
    # readonly_fields = ('current_status', ) 
    # list_editable = ('current_status', )
# admin.site.register(TES_new_Model, TES_admin)
admin.site.register(TES_new_Model)
admin.site.register(TES_otp_model)
admin.site.register(TES_file_upload_model)
admin.site.register(TES_submit_new_house_model, TES_admin)
# admin.site.register(TES_house_visits_model, TES_house_visits_admin)
admin.site.register(TES_template_model)
admin.site.register(TES_report_model)
admin.site.register(TES_superadmin)