from rest_framework import serializers
from .models import TES_new_Model, TES_otp_model, TES_file_upload_model, TES_submit_new_house_model, TES_house_visits_model, TES_template_model, TES_report_model

class TES_Serializer(serializers.ModelSerializer):
    class Meta:
        model = TES_new_Model
        fields = '__all__'

class TES_login_serializer(serializers.ModelSerializer):
    class Meta:
        model = TES_new_Model
        fields = ('email', 'pwd')

class TES_confirm_email_serializer(serializers.ModelSerializer):
    class Meta:
        model = TES_new_Model
        fields = ('email',)

class TES_token_generation(serializers.ModelSerializer):
    class Meta:
        model = TES_new_Model
        fields = ('id', 'email')

class TES_user_profile(serializers.ModelSerializer):
    class Meta:
        model = TES_new_Model
        fields = ('email', 'name', 'addr')

class TES_otp_serializer(serializers.ModelSerializer):
    class Meta:
        model = TES_otp_model
        fields = ('email', 'otp', 'createdAt')

class TES_image_serializer(serializers.ModelSerializer):
    class Meta:
        model = TES_file_upload_model
        fields = ('file', )

class TES_submit_new_house_serializer(serializers.ModelSerializer):
    class Meta:
        model = TES_submit_new_house_model
        fields = ('house_id','addr1','addr2','phone')

class TES_submit_new_house_serializer2(serializers.ModelSerializer):
    class Meta:
        model = TES_submit_new_house_model
        fields = '__all__'

class TES_house_visits_serializer(serializers.ModelSerializer):
    # current_status = serializers.SerializerMethodField()
    class Meta:
        model = TES_house_visits_model
        fields = ('id', 'house_id', 'report_template', 'report_status')

class TES_house_visit_serializer(serializers.ModelSerializer):
    class Meta:
        model = TES_house_visits_model
        fields = '__all__'

class TES_template_serializer(serializers.ModelSerializer):
    class Meta:
        model = TES_template_model
        fields = ('template_name',)

class TES_template_serializer2(serializers.ModelSerializer):
    class Meta:
        model = TES_template_model
        fields = '__all__'

class TES_report_serializer(serializers.ModelSerializer):
    class Meta:
        model = TES_report_model
        fields = ('_id', 'report_name')

class TES_report_serializer2(serializers.ModelSerializer):
    class Meta:
        model = TES_report_model
        fields = '__all__'

class TES_report_serializer3(serializers.ModelSerializer):
    class Meta:
        model = TES_report_model
        fields = ('_id',)
