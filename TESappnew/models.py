# from django.db import models
from __future__ import unicode_literals
from djongo import models
import random as r
import uuid
from django.contrib.auth.hashers import make_password
import hashlib

def image_path(instance, filename):
    gen = uuid.uuid4()
    gen_replace = str(gen).replace("-", str(r.randint(0,9)))
    s = ""
    j = ""
    k = ""
    for i in range(0, len(filename)-1):
        if filename[i] == ".":
            s = i
    for i in range(len(filename)-1, s, -1):
        k = filename[i] + k
    for i in range(0, s):
        j = j + filename[i]
    # file_name_list = filename.split(".")
    # file_name = file_name_list[0]
    # file_ext = file_name_list[1]
    replace_filename = j.replace(j, gen_replace)
    return f'user_image_{replace_filename}.{k}'

class TES_new_Model(models.Model):  
    id = models.ObjectIdField( db_column = "_id", primary_key=True)
    email = models.EmailField(max_length=100, unique=True, blank=False, null=False)
    pwd = models.CharField(max_length=50, blank=False, null=False)
    name = models.CharField(max_length=50)
    addr = models.CharField(max_length=50)

    class Meta:
        db_table = 'TES_data'
        verbose_name_plural = 'TES_data'

    def __str__(self):
        return self.name

class TES_otp_model(models.Model):
    id = models.ObjectIdField( db_column = "_id", primary_key=True)
    email = models.EmailField(max_length=100, unique=True, blank=False, null=False)
    otp = models.CharField(max_length=6)
    createdAt = models.CharField(max_length=100)
    
    class Meta:
        db_table = 'OTP'
        verbose_name_plural = 'OTP'

    def __str__(self):
        return self.otp + " " + self.email
    
class TES_file_upload_model(models.Model):
    id = models.ObjectIdField(db_column="_id", primary_key=True)
    file = models.ImageField(upload_to=image_path, blank=False, null=False)
     
    class Meta:
        db_table = 'uploads'
        verbose_name_plural = 'uploads'
    
class TES_submit_new_house_model(models.Model):
    id = models.ObjectIdField(db_column="_id", primary_key=True)
    customer_id = models.CharField(max_length=100, blank=False, null=False)
    customer_email = models.EmailField(max_length=100, blank=False, null=False)
    house_id = models.CharField(max_length=100, blank=False, null=False)
    addr1 = models.CharField(max_length=100)
    addr2 = models.CharField(max_length=100)
    phone = models.CharField(max_length=100)

    class Meta:
        db_table = 'new_house'
        verbose_name_plural = 'new_house'

    def __str__(self):
        return str(self.id) + " " + self.customer_id + " " + self.customer_email + " " + self.house_id

class TES_report_model(models.Model):
    _id = models.ObjectIdField(db_column="_id", primary_key=True, verbose_name="report_id")
    report_name = models.CharField(max_length=100)
    template_id = models.CharField(max_length=100)

    class Meta:
        db_table = 'reports'
        verbose_name_plural = 'reports'

    def __str__(self):
        return self.report_name + " " + self.template_id

class TES_report_status_model(models.Model):
    _id = models.CharField(max_length=100, primary_key=True)
    report_id = models.CharField(max_length=100, default=None)
    status = models.CharField(max_length=100, default="pending")
    
    class Meta:
        db_table = 'report_status'
        verbose_name_plural = 'report_status'

    def __str__(self):
        return self.report_id + " " + self.status

class TES_house_visits_model(models.Model):
    id = models.ObjectIdField(db_column="_id", primary_key=True)
    house_id = models.CharField(max_length=100)
    customer_id = models.CharField(max_length=100)
    report_template = models.CharField(max_length=100)
    report_status = models.CharField(max_length=100)
    current_status = models.ArrayField(model_container=TES_report_status_model, default=[{"_id":None,"report_id":None, "status":"pending"}])
    
    class Meta:
        db_table = 'house_visits'
        verbose_name_plural = 'house_visits'

    def __str__(self):
        # return self.house_id + " " +self.report_template 
        return  self.house_id + " " + str(self.current_status)

class TES_template_model(models.Model):
    id = models.ObjectIdField(db_column="_id", primary_key=True)
    template_name = models.CharField(max_length=100)

    class Meta:
        db_table = 'templates'
        verbose_name_plural = 'templates'

    def __str__(self):
        return self.template_name

class TES_superadmin(models.Model):
    id = models.ObjectIdField(db_column="_id", primary_key=True)
    email = models.EmailField(max_length=100)
    pwd = models.CharField(max_length=100)

    class Meta:
        db_table = 'TES_superadmin'
        verbose_name_plural = 'TES_superadmin'

    def __str__(self):
        return self.email
    
    # pwd = models.TextField()
    # hash = models.CharField(max_length=64, unique=True, default=None)

    # def save(self, *args, **kwargs):
    #     if self.hash is None:
    #         self.hash = hashlib.sha256(self.pwd).hexdigest()
    #     super().save(*args, **kwargs)

