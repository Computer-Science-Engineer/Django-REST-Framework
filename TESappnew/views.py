from django.shortcuts import render, get_list_or_404 
from rest_framework import viewsets
from TESappnew.paginations import CustomPagination
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
from rest_framework.decorators import api_view, parser_classes ,permission_classes
from django.views.decorators.csrf import csrf_exempt
from .models import TES_new_Model, TES_otp_model, TES_submit_new_house_model, TES_house_visits_model, TES_template_model, TES_report_model, TES_report_status_model, TES_superadmin, TES_file_upload_model
from .serializers import TES_Serializer, TES_login_serializer, TES_confirm_email_serializer, TES_token_generation, TES_user_profile, TES_otp_serializer, TES_image_serializer, TES_submit_new_house_serializer, TES_house_visits_serializer, TES_template_serializer, TES_report_serializer, TES_house_visit_serializer, TES_report_serializer2, TES_report_serializer3, TES_submit_new_house_serializer2, TES_template_serializer2
from django.contrib.auth.hashers import make_password, check_password
from django.http import JsonResponse
from rest_framework.response import Response
# from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
# from rest_framework.generics import RetrieveAPIView, ListAPIView
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
# from bson import ObjectId
# from rest_framework import viewsets
# from django.contrib.auth.models import User
# from rest_framework import authentication 
# from rest_framework import exceptions
# from mongo_auth.permissions import AuthenticatedOnly
from rest_framework_simplejwt.authentication import JWTAuthentication
import requests
import urllib.request
import json
from bson import ObjectId
from rest_framework.schemas import openapi
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
import jwt
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from rest_framework import HTTP_HEADER_ENCODING, authentication
from rest_framework_simplejwt.views import token_verify
from jwt.utils import base64url_decode
import random as r
from datetime import datetime
from rest_framework.parsers import MultiPartParser
import uuid
from rest_framework import generics
from collections import OrderedDict
import ast
from rest_framework.pagination import LimitOffsetPagination, PageNumberPagination
from rest_framework import pagination
import math
from django.views.generic import View
from django.utils.decorators import method_decorator

@api_view(['POST'])
def signup_user(request):
    try:
        data = request.data
        e_v = data["email"]
        p_v = data["pwd"]
        ep_v = make_password(p_v)
        n_v = data["name"]
        a_v = data["addr"]
        try:
             user = TES_new_Model.objects.create(email=e_v, pwd=ep_v, name=n_v, addr=a_v)
             user.save()
             serializer = TES_Serializer(user)
             data_token = TES_new_Model.objects.get(email=e_v)
             take_id = TES_new_Model.objects.only('id').get(email=e_v).id
             access_t = AccessToken.for_user(data_token)
             return JsonResponse({
              "success": True,
              "data": serializer.data,
              "generated_token":{
                    # "id":str(take_id),
                    # "email":serializer.data['email'],
                    "access_token":str(access_t)
              },
              "message": "Signup successful"
               })
        except BaseException:
             return JsonResponse({
              "success": False,
              "data": "",
              "message": "email id already exists or invalid email id"
            })
    except BaseException:
        return JsonResponse({
              "success": False,
              "data": "",
              "message": "missing parameters"
            })

@api_view(['POST'])
def login_user(request):
    try:
        data = request.data
        email_v = data['email']
        pass_v = data['pwd']
        try:
             model_data = TES_new_Model.objects.get(email=email_v)
             serializer = TES_login_serializer(model_data)
        # refresh = RefreshToken.for_user(model_data)
        # if serializer.is_valid():
        # if model_data.email == email_v:
             access_t = AccessToken.for_user(model_data)
             take_id = TES_new_Model.objects.only('id').get(email=email_v).id
             if check_password(pass_v, encoded=model_data.pwd):
                return JsonResponse({
                    "success": True,
                    "data": serializer.data,
                    "generated_token":{
                        # "id":str(take_id),
                        # "email":serializer.data['email'],
                        "access_token": str(access_t),
                        },
                    "message": "Login successful",
                    # "refresh": str(refresh),
                    # "access": str(refresh.access_token)
                    })
             else:
                return JsonResponse({
                    "success": False,
                    "data": "",
                    "message": "Password not matched, Login unsuccessful"
                    })
        except BaseException:
             return JsonResponse({
            "success" : False,
            "data" : "",
            "message":"User not found, Login unsuccessful"
          #   "message" : "login NOT successful because email not found or invalid input or insufficient fields given"
            })
    except BaseException:
        return JsonResponse({
            "success" : False,
            "data" : "",
            "message":"missing parameters"
          #   "message" : "login NOT successful because email not found or invalid input or insufficient fields given"
            })

@api_view(['POST'])
def confirm_user(request):
    try:
        user = request.data
        c_e = user['email']
        model_data = TES_new_Model.objects.get(email=c_e)
        serializer = TES_confirm_email_serializer(model_data)
        return JsonResponse({
                "success":True,
                "data":{
                    # serializer.data,
                "url": 'http://127.0.0.1:8484/TESappnew/reset_pwd'
            },
                "message":"Email id confirmed, click on above link to reset password"})
    except BaseException:
        return JsonResponse({
            "success":False,
            "data":"",
            "message":"User not found"
          #   "message":"Confirm email NOT confirmed because email does not exist or invalid input"
        })

@api_view(['POST'])
def reset_pwd(request):
    try:
        data = request.data
        e_v = data['email']
        p_v = data['pwd']
        try:
             model_data = TES_new_Model.objects.get(email=e_v)
             serializer = TES_login_serializer(model_data)
             if check_password(p_v, encoded=model_data.pwd):
                    return JsonResponse(
                        {
                      "success": False,
                      "data": "",
                      "message": "can't enter old password"})
             else:
                up_v = data['pwd']
                e_up_v = make_password(up_v)
                model_data.pwd = e_up_v
                model_data.save()
                serializer = TES_login_serializer(model_data)
            #   user_data = TES_new_Model.objects.update(pwd=e_up_v)
            #   user_data.save()
            #   serializer = TES_login_serializer(user_data)
                return JsonResponse(
                  {
                "success": True,
                "data": serializer.data,
                "message": "password updated"})
        except BaseException:
          return JsonResponse(
                  {
                "success": True,
                "data": "",
                "message": "User Not Found"})
    except BaseException:
        return JsonResponse(
                  {
                "success": False,
                "data": "",
                "message": "missing parameters"})

@api_view(['POST'])
def gen_token(request):
    try:
         data = request.data
         id_v = data['id']
         email_v = data['email']
         data_token = TES_new_Model.objects.get(email=email_v)
         take_id = TES_new_Model.objects.only('id').get(email=email_v).id
     #     print(take_id)
     #     print(id_v)
         serializer = TES_token_generation(data_token)
        #  refresh_t = RefreshToken.for_user(data_token)
         access_t = AccessToken.for_user(data_token)
         if str(take_id) == id_v:
              return JsonResponse({
                     "success":True,
                     "token":{
                        # "refresh": str(refresh_t),
                        # "access": str(refresh_t.access_token)
                        "access":str(access_t)
                     },
                     "message":"Token generated"
                    #  "message":"correct id and email, token generated"
                   })
         else:
              return JsonResponse({
                     "success":False,
                     "tokens":"",
                     "message":"Invalid ID, token can't be generated"
                   })
    except Exception:
         return JsonResponse({
                     "success":False,
                     "tokens":"",
                    #  "message":"incorrect email or insufficient fields, token can't be generated"
                     "message":"User email not found, token can't be generated"
                   })

# import requests

# class BearerAuth(requests.auth.AuthBase):
#     def __init__(self, token):
#         self.token = token
#     def __call__(self, r):
#         r.headers["authorization"] = "Bearer " + self.token
#         return r

def get_profile(request):
     try:
          token = request.META.get('HTTP_AUTHORIZATION')
          list =  token.split()
          keyword_str = list[0]
          key = list[1]
          key_list = key.split(".")
    #  payload = jwt.decode(jwt=Token)
          header_str = key_list[0]
          payload_str = key_list[1]
          signature_str = key_list[2]
    #  decoded_payload = jwt.decode(payload, settings.SECRET_KEY, algorithms=['HS256'])
    #  id = decoded_payload["user_id"]
          payload = base64url_decode(payload_str)
    #  id = payload
          payload_data = payload.decode('UTF-8')
          payload_data_parse = json.loads(payload_data)
          user_id = payload_data_parse["user_id"]
    #  user_id_str = str(user_id)
          try:
               user_data = TES_new_Model.objects.get(id=ObjectId(user_id))
               serializer = TES_Serializer(user_data)
               if serializer.data["id"] == user_id:
                    return JsonResponse({
        #   "user_data":{
            #  "keyword" : keyword_str,
            #  "header" : header_str,
            #  "payload" : payload_data_parse,
            #  "payload" : payload_str,
            #  "signature": signature_str,
            #  "user_id":user_id,
                         "success":True,
                         "user_data":serializer.data,
                         "message":"user profile"
            #  "payload" : payload_data_parse  
        #   }
                          })
          except BaseException:
               return JsonResponse({
                     "success":False,
                     "data":"",
                     "message":"Unauthenticated access, please login again"
                    })
     except BaseException:
          return JsonResponse({
               "success":False,
               "data":"",
               "message":"INVALID token"
          })

# @api_view(["POST"])
@csrf_exempt
def update_profile(request):
    #  if request.method == "POST":
     try:
          token = request.META.get('HTTP_AUTHORIZATION')
          user = json.loads(request.body)
          list = token.split()
          key = list[1]
          key_list = key.split(".")
          payload_str = key_list[1]
          payload = base64url_decode(payload_str)
          payload_data = payload.decode('UTF-8')
          payload_data_parse = json.loads(payload_data)
          user_id = payload_data_parse["user_id"]
          try:
               get_user = TES_new_Model.objects.get(id=ObjectId(user_id))
               try:
                    updated_user_data = TES_new_Model.objects.filter(id=ObjectId(user_id)).update(email=user["email"], name=user["name"], addr=user["addr"])
                    return JsonResponse({
                     "success":True,
                     "data":"",
                     "message": "profile updated"
                     })
               except BaseException:
                    return JsonResponse({
                      "success":False,
                      "data":"",
                #  "previous data": previous_serializer.data,
                #  "updated data": serializer.data,
                #  "updated data": updated_serializer.data,
                      "message": "missing parameters"
                      })
          except BaseException:
               return JsonResponse({
               "success":False,
               "data":"",
               "message":"Unauthenticated access, please login again"
          })
     except BaseException:
          return JsonResponse({
               "success":False,
               "data":"",
               "message":"INVALID token"
          })
        #   previous_data = TES_new_Model.objects.get(id=ObjectId(user_id))
        #   previous_serializer = TES_Serializer(previous_data)
          
        #   user_data = TES_new_Model.objects.get(id=ObjectId(user_id))
        #   serializer = TES_Serializer(user_data)
        #   updated_serializer = TES_Serializer(updated_user_data)
          

@csrf_exempt
def change_password(request):
     try:
          token = request.META.get('HTTP_AUTHORIZATION')
          user = json.loads(request.body)
          list = token.split()
          key = list[1]
          key_list = key.split(".")
          payload_str = key_list[1]
          payload = base64url_decode(payload_str)
          payload_data = payload.decode('UTF-8')
          payload_data_parse = json.loads(payload_data)
          user_id = payload_data_parse["user_id"]
          try:
               model_data = TES_new_Model.objects.get(id=ObjectId(user_id))
               previous_pwd = user["pwd"]
               new_pwd = user["n_pwd"]
               confirm_pwd = user["c_pwd"]
               if check_password(previous_pwd, encoded=model_data.pwd):
                    if previous_pwd != new_pwd:
                         if(new_pwd == confirm_pwd):
                              e_new_pwd = make_password(new_pwd)
                              updated_pwd = TES_new_Model.objects.filter(id=ObjectId(user_id)).update(pwd=e_new_pwd)
                              return JsonResponse({
                               "success":True,
                               "data":"",
                               "message":"password changed"
                              })
                         else:
                              return JsonResponse({
                            "success":False,
                            "data":"",
                            "message":"new password and confirm password are not same"
                          })
                    else:
                         return JsonResponse({
                         "success":False,
                         "data":"",
                         "message":"new password can't be same as old pwd"
                         })
               else:
                    return JsonResponse({
                       "success":False,
                       "data":"",
                       "message":"current password is wrong"
                    })
          except BaseException:
               return JsonResponse({
                   "success":False,
                   "data":"",
                   "message":"Unauthenticated access, please login again"})
     except BaseException:
          return JsonResponse({
          "success":False,
          "data":"",
          "message":"INVALID token"})

# @csrf_exempt
@api_view(["POST"])
def otp_generation(request):
    #  token = request.META.get('HTTP_AUTHORIZATION')
     user = json.loads(request.body)
     email_v = user["email"]
    #  pwd_v = user["pwd"]
    #  pass_v = user["pwd"]
    #  list = token.split()
    #  key = list[1]
    #  key_list = key.split(".")
    #  payload_str = key_list[1]
    #  payload = base64url_decode(payload_str)
    #  payload_data = payload.decode('UTF-8')
    #  payload_data_parse = json.loads(payload_data)
    #  user_id = payload_data_parse["user_id"]
    #  model_data = TES_new_Model.objects.get(id=ObjectId(user_id))
     try:
             email_data = TES_new_Model.objects.get(email=email_v)
             if email_v == email_data.email:
            #    if check_password(pass_v, encoded=model_data.pwd):
                    serializer = TES_Serializer(email_data)
                    createdAt = datetime.now()
                    createdAt_str = str(createdAt)
                    otp = ""
                    for i in range(6):
                        otp += str(r.randint(1, 9))
                    try:
                        var = TES_otp_model.objects.get(email=email_v)
                        if var:
                             otp_gen = TES_otp_model.objects.filter(email=email_v).update(otp=otp, createdAt=createdAt_str)
                             otp_get_data = TES_otp_model.objects.get(email=email_v)
                    except:
                         otp_gen = TES_otp_model.objects.create(otp=otp, email=email_v, createdAt = createdAt_str)
                         otp_gen.save()
                         otp_get_data = TES_otp_model.objects.get(email=email_v)
                    # take_id = Otp_model.objects.only('id').get(otp=otp).id
                    # otp_get = Otp_model.objects.get(id=ObjectId(take_id))
                    # a_token = AccessToken.for_user(otp_get)
                    otp_serializer = TES_otp_serializer(otp_get_data)
             return JsonResponse({
                          "success":True,
        #  "data":serializer.data,
                          "otp": otp_serializer.data,
                        #   "token_for_verification":str(a_token),
                          "message":"otp generated"})
        # else:
        #      return JsonResponse({
        #                   "success":False,
        # #  "data":serializer.data,
        #                   "otp":"",
        #                 #   "token_for_verification":str(a_token),
        #                   "message":"only email is required"})
     except BaseException:
          return JsonResponse({
               "success":False,
               "data":"",
               "message":"INVALID email id"
          })

# @csrf_exempt
@api_view(["POST"])
def verify_otp(request):
    #  token = request.META.get('HTTP_AUTHORIZATION')
     try:
          s_otp = json.loads(request.body)
          otp_v = s_otp["otp"]
          email_v = s_otp["email"]
    #  list = token.split()
    #  key = list[1]
    #  key_split = key.split(".")
    #  payload_str = key_split[1]
    #  payload = base64url_decode(payload_str)
    #  payload_data = payload.decode('UTF-8')
    #  payload_data_parse = json.loads(payload_data)
    #  otp_id = payload_data_parse["user_id"]
          try:
               otp_data = TES_otp_model.objects.get(email=email_v)
               otp_data_time = otp_data.createdAt
               otp_data_time_obj = datetime.strptime(otp_data_time, '%Y-%m-%d %H:%M:%S.%f')
               otp_data_time_obj_sec = otp_data_time_obj.second
               now_time = datetime.now()
               now_time_sec = now_time.second
               if now_time_sec - otp_data_time_obj_sec <= 10:
                    if otp_v == otp_data.otp:
                         update = TES_otp_model.objects.filter(email=email_v).update(otp="", createdAt="")
                         return  JsonResponse({
                              "success":True,
                              "data":"",
                              "message":"otp verified"
                              })
                    else:
                         return  JsonResponse({
                              "success":False,
                              "data":"",
                              "message":"INVALID OTP"})
               else:
                    update = TES_otp_model.objects.filter(email=email_v).update(otp="", createdAt="")
                    return JsonResponse({
                          "success":False,
                          "data":"",
                          "message":"TIME EXPERIED"})
          except BaseException:
                return JsonResponse({
                   "success":False,
                   "data":"",
                   "message":"INVALID email id"})
     except BaseException:
          return JsonResponse({
                   "success":False,
                   "data":"",
                   "message":"missing parameters"})

class ImageView(APIView):
     parser_classes = (MultiPartParser, )
     def post(self, request, *args, **kwargs):
               # all_images = TES_file_upload_model.objects.all()
               # all_images.delete()
          try:
               serializer = TES_image_serializer(data=request.data)
               if serializer.is_valid():
                    # filename = str(serializer.validated_data["file"])
                    # gen = uuid.uuid4()
                    # gen_replace = str(gen).replace("-", str(r.randint(0,9)))
                    # filename_replace = filename.replace(filename, gen_replace)
                    # serializer.validated_data["file"] = filename_replace
                    serializer.save()
                    # name = serializer.validated_data["file"]
                    # serializer.validated_data["file"] = "hi.png"
                    # serializer.save()
                    # new_name = serializer.validated_data["file"]
                    print(serializer.data)
                    url = "http://127.0.0.1:8484"+serializer.data["file"]
                    str_file = serializer.data["file"]
                    str_file_parts = str_file.split("/")
                    # print(str_file_parts[2])
                    str_file_name = str_file_parts[2]
                    get_image_data = TES_file_upload_model.objects.get(file=str_file_name)
                    get_image_data.delete()
                    return JsonResponse({
                    "success":True,
                    # "filename":serializer.data,
                    # "original filename":serializer.data["file"],
                    "data":url,
                    "message":"image saved"
               })
               else:
                    return JsonResponse({
                    "success":False,
                    "data":"",
                    "message":"upload image"
               })
          except BaseException:
               return JsonResponse({
                    "success":False,
                    "data":"",
                    "message":"upload image"
               })

@api_view(["POST"])
def get_customer_id(request):
     try:
          data = request.data
          email_v = data["email"]
          take_id = TES_new_Model.objects.only('id').get(email=email_v).id
          object_id = ObjectId(take_id)
          return JsonResponse({
                 "success":True,
                 "data":str(object_id),
                 "message":"id of partcular customer "
                })
     except BaseException:
          return JsonResponse({
               "success":False,
               "data":"",
               "message":"INVALID EMAIL"
          })

@csrf_exempt
def submit_new_house(request):
     try:
          token = request.META.get('HTTP_AUTHORIZATION')
          list = token.split()
          key = list[1]
          key_list = key.split(".")
          payload_str = key_list[1]
          payload = base64url_decode(payload_str)
          payload_data = payload.decode('UTF-8')
          payload_data_parse = json.loads(payload_data)
          user_id = payload_data_parse["user_id"]
          try:
               get_user = TES_new_Model.objects.get(id=ObjectId(user_id))
               customer_id = get_user.id
               customer_email = get_user.email
               # house_id = ""
               # for i in range(4):
               #      house_id += str(r.randint(1,9))
               try:
                    data = json.loads(request.body)
                    house_id = data["house_id"]
                    addr1 = data["addr1"]
                    addr2 = data["addr2"]
                    phone = data["phone"]
                    new_house  = TES_submit_new_house_model.objects.create(customer_id=customer_id, customer_email=customer_email ,house_id=house_id, addr1=addr1, addr2=addr2, phone=phone)
                    new_house.save()
    #  serializer = TES_submit_new_house_serializer(new_house)
                    return JsonResponse({
                         "success":True,
                         "data":"",
        #   "data":serializer.data,
                         "message":"new house created"})
               except BaseException:
                    return JsonResponse({
                         "success":False,
                         "data":"",
        #   "data":serializer.data,
                         "message":"missing parameters"})
          except BaseException:
               return JsonResponse({
                 "success":False,
                 "data":"",
                 "message":"Unauthenticated access, please login again"})
     except BaseException:
          return JsonResponse({
                 "success":False,
                 "data":"",
        #   "data":serializer.data,
                 "message":"INVALID token"})

def get_house_list(request):
# class get_house_list(generics.ListAPIView):
#      serializer_class = TES_submit_new_house_serializer
#      def get_queryset(self, request):
     try:
          token = request.META.get('HTTP_AUTHORIZATION')
          list = token.split()
          key = list[1]
          key_list = key.split(".")
          payload_str = key_list[1]
          payload = base64url_decode(payload_str)
          payload_data = payload.decode('UTF-8')
          payload_data_parse = json.loads(payload_data)
          customer_id = payload_data_parse["user_id"]
          # print(str(customer_id))
          try:
               get_user = TES_new_Model.objects.get(id=ObjectId(customer_id))
               houses = TES_submit_new_house_model.objects.all()
               houses_list = houses.filter(customer_id=customer_id)
               serializer = TES_submit_new_house_serializer(houses_list, many=True)
               if len(serializer.data) != 0:
                    return JsonResponse({
                      "success":True,
                      "data":serializer.data,
          # "message":f"list of houses of {serializer.data[0]['customer_id']}"
                      "message":f"list of houses of {customer_id}"})
               else:
                    return JsonResponse({
                      "success":False,
                      "data":"",
          # "message":f"list of houses of {serializer.data[0]['customer_id']}"
                      "message":f"no houses registered of customer {customer_id}"})
          except BaseException:
               return JsonResponse({
               "success":False,
               "data":"",
               "message":"Unauthenticated access, please login again"
          })
     except BaseException:
          return JsonResponse({
               "success":False,
               "data":"",
               "message":"invalid token"
          })

@csrf_exempt
def create_visit(request):
     try:
          token = request.META.get('HTTP_AUTHORIZATION')
          list = token.split()
          key = list[1]
          key_list = key.split(".")
          payload_str = key_list[1]
          payload = base64url_decode(payload_str)
          payload_data = payload.decode('UTF-8')
          payload_data_parse = json.loads(payload_data)
          customer_id = payload_data_parse["user_id"]
          try:
               get_user = TES_new_Model.objects.get(id=ObjectId(customer_id))
               try:
                    data = json.loads(request.body)
                    house_id_v = data["house_id"]
                    report_template = data["report_template"]
                    report_status = data["report_status"]
                    '''
                    all_records_deleted = TES_house_visits_model.objects.all().delete()
                    '''
          # all_reports = TES_report_model.objects.all()
          
          # print(len(report_serializer.data))
          # a = []
          # for i in range(0, len(report_serializer.data)):
          #      current_status = a.append(json.dumps({report_serializer.data[i]["id"]:"pending"}))
          
                    '''
                    l = [dict(zip([report_serializer.data[x]["_id"]],["pending"])) for x in range(0, len(report_serializer.data))]
                    for i in range(0, len(l)):
                       l[i]["_id"] = report_serializer.data[i]["_id"]
                       l[i]["report_name"] = report_serializer.data[i]["report_name"]
                       l[i]["template_id"] = report_serializer.data[i]["template_id"]
                       l[i] = {**l[i], **{"status":"pending"}}
                       print(l[i])
                       print(l)
                    '''
                    '''
                    l = [dict(zip(["status"],["pending"])) for x in range(0, len(report_serializer.data))]
                    for i in range(0, len(l)):
                         l[i]["_id"] = report_serializer.data[i]["_id"]
                         l[i]["report_name"] = report_serializer.data[i]["report_name"]
                         l[i]["template_id"] = report_serializer.data[i]["template_id"]
                    print(l)
                    '''
            

          # for i in range(0, len(report_serializer.data)):
          #      l[i]["_id"] = report_serializer.data[i]["_id"]
          #      l[i]["report_name"] = report_serializer.data[i]["report_name"]
          #      l[i]["template_id"] = report_serializer.data[i]["template_id"]
          #      d = {**l[i], **{"status":"pending"}}
          # get_customer = TES_submit_new_house_model.objects.filter(customer_id=customer_id)
          # get_customer_serializer = TES_submit_new_house_serializer(get_customer, many=True)
                    try:
          # while True:
                         particular_reports = TES_report_model.objects.filter(template_id=report_template)
                         report_serializer = TES_report_serializer3(particular_reports, many=True)
                         if len(report_serializer.data) != 0:
                              l=[]
                              for i in range(0, len(report_serializer.data)):
                                   l.append(
                                     {
                                        "_id":uuid.uuid4(),
                                        "report_id":report_serializer.data[i]["_id"],
                                        "status":"pending"
                                      })
          # while True:
                              get_house = TES_submit_new_house_model.objects.get(house_id=house_id_v)
          # if get_house.customer_id == customer_id:
          # if get_customer_serializer.data[0]["house_id"] == house_id_v:
          # get_house = TES_submit_new_house_model.objects.get(house_id=house_id_v)
          # if TES_submit_new_house_model.objects.get(house_id=house_id_v).house_id == house_id_v:
                              create_visit = TES_house_visits_model.objects.create(house_id=house_id_v, customer_id=customer_id ,report_template=report_template, report_status=report_status, current_status=l)
                              create_visit.save()
               # previous_visits = TES_house_visits_model.objects.filter(customer_id=customer_id)
               # serializer = TES_house_visits_serializer(previous_visits, many=True)
                              return JsonResponse({
                                  "success":True,
               # "total_visits":serializer.data,
                                  "data":"",
                                  "message":f"new visit at house id {house_id_v} of customer -> {customer_id}"})
                         else:
                              return JsonResponse({
                                   "success":False,
                                   "data":"",
                                   "message":"Invalid report template"})
          
                    except BaseException:
                         return JsonResponse({
                             "success":False,
                             "data":"",
                             "message":"Invalid house ID"})
               except BaseException:
                    return JsonResponse({
                           "success":False,
                           "data":"",
                           "message":"Missing parameters"})
          except BaseException:
               return JsonResponse({
               "success":False,
               "data":"",
               "message":"Unauthenticated access, please login again"})
     except BaseException:
          return JsonResponse({
               "success":False,
               "data":"",
               "message":"INVALID TOKEN"})

def get_visits(request):
     try:
          token = request.META.get('HTTP_AUTHORIZATION')
          list = token.split()
          key = list[1]
          key_list = key.split(".")
          payload_str = key_list[1]
          payload = base64url_decode(payload_str)
          payload_data = payload.decode('UTF-8')
          payload_data_parse = json.loads(payload_data)
          customer_id = payload_data_parse["user_id"]
          try:
               get_user = TES_new_Model.objects.get(id=ObjectId(customer_id))
               visits  = TES_house_visits_model.objects.filter(customer_id=customer_id)
               serializer = TES_house_visits_serializer(visits, many=True)
               serializer2 = TES_house_visit_serializer(visits, many=True)
               if len(serializer.data) != 0:
                    l = []
                    for i in range(len(serializer.data)):
                         l.append({
                              **serializer.data[i],
                              **{"current_status":json.loads(serializer2.data[i]["current_status"])}
                         })
                    return JsonResponse({
                        "success":True,
               # "data":json.loads(serializer.data[5]["current_status"]),
                        "data":l,
               # "data":serializer2.data,
                        "message":f"total visits of customer -> {customer_id}"})
               else:
                    return JsonResponse({
               "success":False,
               "data": "",
               "message":f"no house visit registered of customer -> {customer_id}"})
          except BaseException:
               return JsonResponse({
               "success":False,
               "data": "",
               "message":"Unauthenticated access, please login again"
          })
          # data = get_list_or_404(TES_house_visits_model, customer_id=customer_id)
          # serializer = TES_house_visit_serializer(data, many=True)
     except BaseException:
          return JsonResponse({
               "success":False,
               "data": "",
               "message":"INVALID token"
          })

@api_view(["POST"])
def create_template(request):
     try:
          data = json.loads(request.body)
          t_n = data["template_name"]
          new_template = TES_template_model.objects.create(template_name=t_n)
          new_template.save()
          return JsonResponse({
             "success":True,
             "data":"",
             "message":"new template created"
            })
     except BaseException:
          return JsonResponse({
               "success":False,
               "data":"",
               "message":"Invalid input"
          })

@api_view(["POST"])
def create_report(request):
     try:
          data = json.loads(request.body)
          r_n = data["report_name"]
          t_id = data["template_id"]
          template_data = TES_template_model.objects.filter(id=ObjectId(t_id))
     # take_id = TES_template_model.objects.only('id').get(id=ObjectId(t_id)).id
          print(template_data[0].id)
          # if str(template_data[0].id) == t_id:
          new_report = TES_report_model.objects.create(report_name=r_n, template_id=t_id)
          new_report.save()
          return JsonResponse({
               "success":True,
               "data":"",
               "message":f"new report submitted to id {t_id} "
           })
     # else:
     #      return JsonResponse({
     #      "success":False,
     #      "data":"",
     #      "message":"ID not found"
     #       })
     except BaseException:
          return JsonResponse({
               "success":False,
               "data":"",
               "message":"ID not found"
           })

@api_view(["POST"])
def get_reports_list(request):
     try:
          data = json.loads(request.body)
          t_id = data["template_id"]
          reports_list = TES_report_model.objects.filter(template_id=t_id)
          serializer = TES_report_serializer(reports_list, many=True)
          if reports_list:
               return JsonResponse({
                  "success":True,
                  "data":serializer.data,
                  "message": f"list of reports related to particular template {t_id}"
               })
          else:
             return JsonResponse({
                  "success":False,
                  "data":"",
                  "message": "template id NOT found"
          })
     except BaseException:
          return JsonResponse({
             "success":False,
             "data":"",
             "message": "template id NOT found"
          })

@api_view(["POST"])
def visit_details(request):
     try:
          data = json.loads(request.body)
          visit_id = data["visit_id"]
          visit_detail = TES_house_visits_model.objects.get(id=ObjectId(visit_id))
          # get_temp_id = visit_detail.report_template
          serializer = TES_house_visits_serializer(visit_detail)
          serializer2 = TES_house_visit_serializer(visit_detail)
          data = {**serializer.data, **{"current_status":json.loads(serializer2.data["current_status"])}}
          '''
          reports_list = TES_report_model.objects.filter(template_id=get_temp_id)
          report_serializer = TES_report_serializer2(reports_list, many=True)
          data = {**serializer.data, **{"reports":report_serializer.data}}
          '''
          # serializer2 = Visit_serializer(visit_detail, reports_list, many=True)
          # serializer2.is_valid()
          # print(dict(visit_detail).items())
     # if visit_detail:.
          return JsonResponse({
               "success":True,
               "data":data,
               # "data":serializer.data,
               # "data":serializer2.data,
               "message":"visit detail of particular visit id with reports of particular template"
          })
     except BaseException:
          return JsonResponse({
               "success":False,
               "data":"",
               "message":"INVALID visit id"
          })

@csrf_exempt
def check_report_status(request):
     try:
          token = request.META.get('HTTP_AUTHORIZATION')
          list = token.split()
          key = list[1]
          key_list = key.split(".")
          payload_str = key_list[1]
          payload = base64url_decode(payload_str)
          payload_data = payload.decode('UTF-8')
          payload_data_parse = json.loads(payload_data)
          user_id = payload_data_parse["user_id"]
          try:
               data = json.loads(request.body)
               visit_id = data["visit_id"]
               report_id = data["report_id"]
     # get_visits = TES_house_visits_model.objects.filter(customer_id=user_id)
               try:
                    get_user = TES_new_Model.objects.get(id=ObjectId(user_id))
                    try:
                         get_particular_visit = TES_house_visits_model.objects.get(id=ObjectId(visit_id))
                         '''
                         Now we will check customer 
                         using user id which we get
                         from generated token 
                         '''
          # if get_particular_visit.customer_id == user_id:
          #      # current_temp = get_particular_visit.report_template
          #      get_particular_report = TES_house_visits_model.objects.filter(
          #           current_status = [ { 
          #           #     "_id": get_particular_visit.current_status[0]["_id"],
          #               "report_id": report_id
          #           #     "status":"pending"
          #           } ]
          #      ).update( current_status=
          #                 [ {
          #                     "_id": get_particular_visit.current_status[0]["_id"],
          #                     "report_id":report_id,
          #                     "status":"completed"
          #                     # get_particular_visit.current_status[0]["status"]:"completed"
          #                  } ]
          #      )
                         serializer = TES_house_visit_serializer(get_particular_visit)
                         if serializer.data["customer_id"] == user_id:
                              update = serializer.data["current_status"]
          # print(serializer.data)
                    
                              update_json = json.loads(update)
          # print(update_json[0]["report_id"])
          # print(len(update_json))
                              try:
                                   for i in range(len(update_json)):
                                        if update_json[i]["report_id"] == report_id:
                                             i_v = i
                                   update_status = update_json[i_v]["status"]
          # print(update_status)
                                   update_status = update_status.replace("pending","completed")
                                   t = tuple(zip(update_json[i_v].keys(), update_json[i_v].values()))
                                   dict_t = dict(t)
                                   dict_t["status"] = update_status
          # print(dict_t)
          # print(serializer.data)
          # print(update)
                                   k = update_json[i_v]
                                   l = dict_t
                                   r = k.update(l)
          # print(k)
                                   get_particular_visit.current_status[i_v].update(k)
                                   get_particular_visit.save()
                                   serializer = TES_house_visit_serializer(get_particular_visit)
          # l3 = []
          # l3.append(dict(t[2]))
          # print(l3[0][1])
          # l3[0][1] = update_status
          # print(update_status)
          # d = {"status" : update_status}
          # update_json[i_v].update(d)
          # print(update_json[i_v])
          # l1 = []
          # print(update_json[i_v].items())
          # print(list(update_json[i_v].items()))
          # print(update_json_list)
               # if get_particular_report.template_id == current_temp:
               # updated_status = TES_report_model.objects.filter(id=ObjectId(report_id)).update(status="completed")
               # get_particular_report = TES_report_model.objects.get(id=ObjectId(report_id))
               # serializer = TES_report_serializer2(get_particular_report)
                                   return JsonResponse({
                                      "success":True,
                                      "data":json.loads(serializer.data["current_status"]),
                                      "message":"status updated"})
                              except BaseException:
                                   return JsonResponse({
                                       "success":False,
                                       "data":"",
                                       "message":"invalid report id"})
                         else:
                              return JsonResponse({
                                  "success":False,
                                  "data":"",
                                  "message":"Customer ID and Visit ID mismatched"})
                    except BaseException:
                         return JsonResponse({
                               "success":False,
                               "data":"",
                               "message":"invalid visit id"})
               except BaseException:
                    return JsonResponse({
                            "success":False,
                            "data":"",
                            "message":"Unauthenticated access, please login again"})
          except BaseException:
                    return JsonResponse({
                            "success":False,
                            "data":"",
                            "message":"missing parameters"})
               # else:
               #     return JsonResponse({
               #     "success":False,
               #     "data":"",
               #     "message":"INVALID template id"
               #  })
               # get_visits_serializer = TES_house_visit_serializer(get_visits, many=True)
               # get_temp = get_visits_serializer.data[0]["report_template"]
          #      get_report = TES_report_model.objects.filter(template_id=get_temp)
          #      get_report_serializer = TES_report_serializer2(get_report, many=True)
          #      get_particular_report = TES_report_model.objects.get(id=ObjectId(report_id))
          #      get_particular_report_serializer = TES_report_serializer(get_particular_report)
          #      if get_particular_report.template_id == get_temp:
          #           return JsonResponse({
          #           "success":True,
          #           "data":get_particular_report_serializer.data,
          # # "keys":str(get_visits_serializer.data.keys()),
          # # "data":str(get_visits_serializer.data.values()),
          #           "message":"report status"
          #            })
          #      else:
          #           return JsonResponse({
          #          "success":False,
          #          "data":"",
          #          "message":"INVALID report or template"
          #           })
          # else:
          #      return JsonResponse({
          #          "success":False,
          #          "data":"",
          #          "message":"INVALID token 1"
          #       })
     except BaseException:
          return JsonResponse({
                   "success":False,
                   "data":"",
                   "message":"INVALID token"
               })

        #        except BaseException:
        #             return JsonResponse({
        #             "success":False,
        #             "data":"",
        #             "message":"NOT saved"
        #        })

# class HouseList(generics.ListAPIView):
#      serializer_class = TES_submit_new_house_serializer

# @parser_classes((MultiPartParser, ))
# @api_view(["POST"])
# def image_upload(request):
#     #  try:
#           image = request.FILES["file"]
#         #   rmk = request.data["rmk"]
#           serializer = TES_image_serializer(image["rmk"])
#           serializer.is_valid()
#           return JsonResponse({
#              "success":True,
#              "data":serializer.data['rmk'],
#              "message":"image saved"})
    #  except BaseException:
    #       return JsonResponse({
    #          "success":False,
    #          "data8":"",
    #          "message":"image CAN'T be saved"})


# class Home(APIView):
    #  def post(self, request, *args, **kwargs):
        #   print("request is ", request._request)
        #   verify_token_response = token_verify(request._request)
        #   print("status code is ", verify_token_response.status_code)
        #   if(verify_token_response.status_code == 200):
        #        jwt_object = JWTAuthentication()
        #        header = jwt_object.get_header(request)
        #        raw_token = jwt_object.get_raw_token(header)
        #        validated_token = jwt_object.get_validated_token(raw_token)
        #        user = jwt_object.get_user(validated_token)
        #        print(user)

@api_view(["POST"])
def TES_superadmin_login(request):
     data = request.data
     email = data["email"]
     pwd = data["pwd"]
     try:
          get_superadmin = TES_superadmin.objects.get(email=email)
          if check_password(pwd, encoded=get_superadmin.pwd):
               access_t = AccessToken.for_user(get_superadmin)
               return JsonResponse({
               "success":True,
               "data":"",
               "token_generated":{
                  "access_token":str(access_t)
               },
               "message":"login successful"
          })
          else:
               return JsonResponse({
               "success":False,
               "data":"",
               "message":"login unsuccessful"
          })
     except BaseException:
          return JsonResponse({
               "success":False,
               "data":"",
               "message":"login unsuccessful"
          })

@csrf_exempt
def get_all_users(request):
     try:
          token = request.META.get('HTTP_AUTHORIZATION')
          list = token.split()
          key = list[1]
          key_list = key.split(".")
          payload_str = key_list[1]
          payload = base64url_decode(payload_str)
          payload_data = payload.decode('UTF-8')
          payload_data_parse = json.loads(payload_data)
          user_id = payload_data_parse["user_id"]
          try:
          # while True:
               get_superadmin = TES_superadmin.objects.get(id=ObjectId(user_id))
               try:
               # while True:
                    # all_users = TES_new_Model.objects.all()
                    # serializer = TES_Serializer(all_users, many=True)
                    data = json.loads(request.body)
                    search = data["search"]
                    res1 = TES_new_Model.objects.filter(email__icontains = search)
                    res2 = TES_new_Model.objects.filter(name__icontains = search)
                    res3 = TES_new_Model.objects.filter(addr__icontains = search)
                    serializer1 = TES_Serializer(res1, many=True)
                    serializer2 = TES_Serializer(res2, many=True)
                    serializer3 = TES_Serializer(res3, many=True)
                    l = serializer1.data+serializer2.data+serializer3.data
                    if l or search == "":
                         res = []
                         [res.append(x) for x in l if x not in res]
                         return JsonResponse({
                         "success":True,
                         "data":res,
                         "message": f"search result of {search}"
                    })
                    else:
                         return JsonResponse({
                         "success":False,
                         "data":"",
                         "message":"search not found"
                    })
               except:
                    # return JsonResponse({
                    #      "success":False,
                    #      "data":"",
                    #      "message":"search not found"
                    # })
                    all_users = TES_new_Model.objects.all()
                    serializer = TES_Serializer(all_users, many=True)
                    return JsonResponse({
                         "success":True,
                         "data":serializer.data,
                         "message":"list of all users"
                    })
          except BaseException:
               return JsonResponse({
               "success":False,
               "data":"",
               "message":"not admin"
          })
     except BaseException:
             return JsonResponse({
               "success":False,
               "data":"",
               "message":"Invalid token"
          })

@csrf_exempt
def get_all_houses(request):
     try:
          token = request.META.get('HTTP_AUTHORIZATION')
          list = token.split()
          key = list[1]
          key_list = key.split(".")
          payload_str = key_list[1]
          payload = base64url_decode(payload_str)
          payload_data = payload.decode('UTF-8')
          payload_data_parse = json.loads(payload_data)
          user_id = payload_data_parse["user_id"]
          try:
          # while True:
               get_superadmin = TES_superadmin.objects.get(id=ObjectId(user_id))
               try:
               # while True:
                    data = json.loads(request.body)
                    search = data["search"]
                    # records = data["records"]
                    res1 = TES_submit_new_house_model.objects.filter(house_id__contains=search)
                    res2 = TES_submit_new_house_model.objects.filter(phone__contains=search)
                    res3 = TES_submit_new_house_model.objects.filter(customer_email__icontains=search)
                    res4 = TES_submit_new_house_model.objects.filter(addr1__icontains=search)
                    res5 = TES_submit_new_house_model.objects.filter(addr2__icontains=search)
                    # res6 = TES_submit_new_house_model.objects.filter(customer_id__icontains=search)
                    # if res1:
                    serializer1 = TES_submit_new_house_serializer2(res1, many=True)
                    #      return JsonResponse({
                    #         "success":True,
                    #         "data":serializer.data,
                    #         "message":f"search result of {search}"
                    # })
                    # elif res2:
                    serializer2 = TES_submit_new_house_serializer2(res2, many=True)
                    #      return JsonResponse({
                    #         "success":True,
                    #         "data":serializer.data,
                    #         "message":f"search result of {search}"
                    # })
                    # elif res3:
                    serializer3 = TES_submit_new_house_serializer2(res3, many=True)
                    #      return JsonResponse({
                    #         "success":True,
                    #         "data":serializer.data,
                    #         "message":f"search result of {search}"
                    # })
                    # elif res4:
                    serializer4 = TES_submit_new_house_serializer2(res4, many=True)
                    #      return JsonResponse({
                    #         "success":True,
                    #         "data":serializer.data,
                    #         "message":f"search result of {search}"
                    # })
                    # elif res5:
                    serializer5 = TES_submit_new_house_serializer2(res5, many=True)
                    #      return JsonResponse({
                    #         "success":True,
                    #         "data":serializer.data,
                    #         "message":f"search result of {search}"
                    # })
                    # elif res6:
                    # serializer6 = TES_submit_new_house_serializer2(res6, many=True)
                    #      return JsonResponse({
                    #         "success":True,
                    #         "data":serializer.data,
                    #         "message":f"search result of {search}"
                    # })
                    # else:
                    #      return JsonResponse({
                    #           "success":False,
                    #           "data":"",
                    #           "message":"no record found"
                    # })
                    l = serializer1.data+serializer2.data+serializer3.data+serializer4.data+serializer5.data
                    if l or search == "":
                         res = []
                         [res.append(x) for x in l if x not in res]
                         # paginator = PageNumberPagination()
                         # paginator.page_size = 10
                         # result_page = paginator.paginate_queryset(res, request)
                         # q = paginator.get_paginated_response(res)
                         return JsonResponse({
                            "success":True,
                            "data":res,
                            "message":f"search result of {search}"
                    })
                    else:
                         return JsonResponse({
                            "success":False,
                            "data":"",
                            "message":"search not found"
                    })
               #      if TES_submit_new_house_model.objects.filter(house_id__contains=search):
               #           res = TES_submit_new_house_model.objects.filter(house_id__contains=search)
               #           serializer = TES_submit_new_house_serializer2(res, many=True)
               #           return JsonResponse({
               #           "success":True,
               #           "data":serializer.data,
               #           "message":f"search result of {search}"
               #      })
               #      elif TES_submit_new_house_model.objects.filter(phone__contains=search):
               #           res = TES_submit_new_house_model.objects.filter(phone__contains=search)
               #           serializer = TES_submit_new_house_serializer2(res, many=True)
               #           return JsonResponse({
               #           "success":True,
               #           "data":serializer.data,
               #           "message":f"search result of {search}"
               #      })
               #      elif TES_submit_new_house_model.objects.filter(customer_email__icontains=search):
               #           res = TES_submit_new_house_model.objects.filter(customer_email__icontains=search)
               #           serializer = TES_submit_new_house_serializer2(res, many=True)
               #           return JsonResponse({
               #           "success":True,
               #           "data":serializer.data,
               #           "message":f"search result of {search}"
               #      })
               #      elif TES_submit_new_house_model.objects.filter(addr1__icontains=search):
               #           res = TES_submit_new_house_model.objects.filter(addr1__icontains=search)
               #           serializer = TES_submit_new_house_serializer2(res, many=True)
               #           return JsonResponse({
               #           "success":True,
               #           "data":serializer.data,
               #           "message":f"search result of {search}"
               #      })
               #      elif TES_submit_new_house_model.objects.filter(addr2__icontains=search):
               #           res = TES_submit_new_house_model.objects.filter(addr2__icontains=search)
               #           serializer = TES_submit_new_house_serializer2(res, many=True)
               #           return JsonResponse({
               #           "success":True,
               #           "data":serializer.data,
               #           "message":f"search result of {search}"
               #      })
               #      elif TES_submit_new_house_model.objects.filter(customer_id__icontains=search):
               #           res = TES_submit_new_house_model.objects.filter(customer_id__icontains=search)
               #           serializer = TES_submit_new_house_serializer2(res, many=True)
               #           return JsonResponse({
               #                "success":True,
               #                "data":serializer.data,
               #                "message":f"search result of {search}"
               #      })
               #      else:
               #          return JsonResponse({
               #                "success":False,
               #                "data":"",
               #                "message":"no record found"
               #      })
               except:
          # while True:
                    # paginator = PageNumberPagination()
                    # paginator.page_size = 2
                    # all_houses = TES_submit_new_house_model.objects.all()
                    # all_houses2 = TES_submit_new_house_model.objects.all()[11:]
                    # paginator = Paginator(all_houses, 5)
                    # page_number = request.query_params.get(self.page_query_param, 1)
                    # result_page = paginator.paginate_queryset(all_houses, request)
                    # serializer = TES_submit_new_house_serializer2(all_houses, many=True)
                    # serializer2 = TES_submit_new_house_serializer2(all_houses2, many=True)
                    # houses = paginator.get_paginated_response(serializer.data)
                    # pagination.PageNumberPagination.page_size = 2
                    # paginator = LimitOffsetPagination()
                    # result_page = paginator.paginate_queryset(all_houses, request)
                    # serializer = TES_submit_new_house_serializer2(result_page, many=True)
                    # response = JsonResponse(serializer.data)
                    return JsonResponse({ 
                         "success":False,
                         # "success":True,
                         "data":"",
                         # "data":serializer.data,
                         # "data":houses,
                         # "message":"list of all houses"
                         "message":"search not found"
                    })
          except BaseException:
               return JsonResponse({
               "success":False,
               "data":"",
               "message":"not admin"
          })
     except BaseException:
             return JsonResponse({
               "success":False,
               "data":"",
               "message":"Invalid token"
          })
     '''
                    all_houses = TES_submit_new_house_model.objects.all()
                    serializer = TES_submit_new_house_serializer2(all_houses, many=True)
                    hil = []
                    cel = []
                    pl = []
                    al = []
                    al2 = []
                    cil = []
                    for i in range(len(serializer.data)):
                         hil.append(serializer.data[i]["house_id"])
                         cel.append(serializer.data[i]["customer_email"])
                         pl.append(serializer.data[i]["phone"])
                         al.append(serializer.data[i]["addr1"])
                         al2.append(serializer.data[i]["addr2"])
                         cil.append(serializer.data[i]["customer_id"])
                    # print(hil)
                    # print(cel)
                    # print(pl)
                    # print(al)
                    # for i in range(len(hil)):
                    if search in hil:
                         get_house = TES_submit_new_house_model.objects.filter(house_id=search)
                         serializer_h = TES_submit_new_house_serializer2(get_house, many=True)
                         return JsonResponse({
                                      "success":True,
                                       "data":serializer_h.data,
                                       "message":f"search result of {search}"
                              })
                    # elif search not in hil and search not in pl and search not in cel and search not in al and search not in al2 and search != "":     
                    # elif search not in hil and search != "":
                    elif search in pl:
                         get_house = TES_submit_new_house_model.objects.filter(phone=search)
                         serializer_h = TES_submit_new_house_serializer2(get_house, many=True)
                         return JsonResponse({
                         "success":True,
                         "data":serializer_h.data,
                         "message":f"search result of {search}"
                          })
                    elif search in cel:
                         get_house = TES_submit_new_house_model.objects.filter(customer_email=search)
                         serializer_h = TES_submit_new_house_serializer2(get_house, many=True)
                         return JsonResponse({
                         "success":True,
                         "data":serializer_h.data,
                         "message":f"search result of {search}"
                          })
                    elif search in al:
                         get_house = TES_submit_new_house_model.objects.filter(addr1=search)
                         serializer_h = TES_submit_new_house_serializer2(get_house, many=True)
                         return JsonResponse({
                         "success":True,
                         "data":serializer_h.data,
                         "message":f"search result of {search}"
                         })
                    elif search in al2:
                         get_house2 = TES_submit_new_house_model.objects.filter(addr2=search)
                         serializer_h2 = TES_submit_new_house_serializer2(get_house2, many=True)
                         return JsonResponse({
                         "success":True,
                         "data":serializer_h2.data,
                         "message":f"search result of {search}"
                          })
                    elif search == "":
                         return JsonResponse({
                         "success":True,
                         "data":serializer.data,
                         "message":"list of all houses"
                          })
                    elif search != "":
                         hid = []
                         lpl = []
                         for i in range(len(hil)):
                              if hil[i].__contains__(search):
                                   hid.append(hil[i])
                         for j in range(len(pl)):
                              if pl[j].__contains__(search):
                                   lpl.append(pl[j])
                         # print(hid)
                         # print(lpl)
                         sl = []
                         sl2 = []
                         for i in range(len(hid)):
                              get_house = TES_submit_new_house_model.objects.filter(house_id=hid[i])
                              serializer_h = TES_submit_new_house_serializer2(get_house, many=True)
                              sl.append(serializer_h.data)
                         for i in range(len(lpl)):
                              get_house = TES_submit_new_house_model.objects.filter(phone=lpl[i])
                              serializer_h2 = TES_submit_new_house_serializer2(get_house, many=True)
                              sl2.append(serializer_h2.data)
                         # print(len(sl2))
                         # print(sl2)
                         b = []
                         for i in range(len(sl)):
                               b.append(sl[i][0])
                         # for i in range(len(sl)):
                         #       b.append(sl[i])
                         return JsonResponse({
                                      "success":True,
                                       "data":b,
                                       "message":f"search result of {search}"
                                   })
                    # if search in hil:
                    #      get_house = TES_submit_new_house_model.objects.filter(house_id=search)
                    #      serializer_h = TES_submit_new_house_serializer2(get_house, many=True)
                    #      return JsonResponse({
                    #                   "success":True,
                    #                    "data":serializer_h.data,
                    #                    "message":f"search result of {search}"
                    #       })
                    # else:
                    #      get_house = TES_submit_new_house_model.objects.filter(house_id=search)
                    #      serializer_h = TES_submit_new_house_serializer2(get_house, many=True) 
                    #      for i in range(len(hil)):
                    #           if hil[i].__contains__(search):
                    #                 return JsonResponse({
                    #                   "success":True,
                    #                    "data":serializer_h.data,
                    #                    "message":f"search result of {search}"
                    #       })

                    elif search in cil:
                         get_house = TES_submit_new_house_model.objects.filter(customer_id=search)
                         serializer = TES_submit_new_house_serializer2(get_house, many=True)
                         return JsonResponse({
                         "success":True,
                         "data":serializer.data,
                         "message":f"search result of {search}"
                          })
                    else:
                         return JsonResponse({
                         "success":False,
                         "data":"",
                         "message":"search not found"
                          })
     '''

class HousesViewSet(viewsets.ModelViewSet):
     queryset = TES_submit_new_house_model.objects.all()
     serializer_class = TES_submit_new_house_serializer2
     def refunc(self):
          queryset = TES_submit_new_house_model.objects.all()
          pagination_class = PageNumberPagination
          paginator = self.django_paginator_class(queryset, 10)
     # def refunc():
     #      queryset = TES_submit_new_house_model.objects.all()
     #      count = Paginator.count
     #      pages = math.ceil(count/10)
     #      serializer = TES_submit_new_house_serializer2(queryset, many=True)
     #      return JsonResponse({
     #      "success":True,
     #      "pages":pages,
     #      "data":serializer.data
     # })

class HousesViewSet2(viewsets.ModelViewSet):
     queryset = TES_submit_new_house_model.objects.all()
     serializer_class = TES_submit_new_house_serializer2
     pagination_class = PageNumberPagination
     def get_paginated_response(self, data):
         queryset = TES_submit_new_house_model.objects.all()
         serializer2  = TES_submit_new_house_serializer2(queryset, many=True)
     #     print(type(data))
         return JsonResponse(OrderedDict([
          #   ('count', self.page.paginator.count),
          #   ('next', self.get_next_link()),
          #   ('previous', self.get_previous_link()),
            ('success', True),
          #   ('data', data ),
            ('data',{**{'total_pages': math.ceil(len(serializer2.data)/10)}, **{"records":data}}),
            ('message', 'all paginated records')
        ]))
     def list(self,request):
          houses_data = TES_submit_new_house_model.objects.all()
          serializer2 = TES_submit_new_house_serializer2(houses_data, many=True)
          dictrec = {**{"total_pages": math.ceil(len(serializer2.data)/10)},**{"records":""}}
          try:
          # while True:
              page = self.paginate_queryset(houses_data)
     #     paginator = self.django_paginator_class(houses_data, 10)
              if page is not None:
                   serializer = self.get_serializer(page, many=True)
          #     data = self.get_paginated_response(serializer.data)
          #     return self.get_paginated_response(serializer.data)
                   pr = self.get_paginated_response(serializer.data)
               #     print(len(serializer.data))
                   return pr
          except:
               return JsonResponse({
                    "success":False,
                    "data":dictrec,
                    "message":"Invalid page"
               })

# @api_view(['POST',])
@csrf_exempt
def PWS(request):
     try:
     # while True:
          token = request.META.get('HTTP_AUTHORIZATION')
          list = token.split()
          key = list[1]
          key_list = key.split(".")
          payload_str = key_list[1]
          payload = base64url_decode(payload_str)
          payload_data = payload.decode('UTF-8')
          payload_data_parse = json.loads(payload_data)
          user_id = payload_data_parse["user_id"]
          try:
          # while True:
               get_superadmin = TES_superadmin.objects.get(id=ObjectId(user_id))
               try:
               # while True:
                    page = request.GET.get('page')
                    search = request.GET.get('search')
                    # print(page)
                    # print(search)
                    # res7 = TES_submit_new_house_model.objects.filter(house_id__contains=search).order_by('house_id')
                    res1 = TES_submit_new_house_model.objects.filter(house_id__contains=search)
                    res2 = TES_submit_new_house_model.objects.filter(phone__contains=search)
                    res3 = TES_submit_new_house_model.objects.filter(customer_email__icontains=search)
                    res4 = TES_submit_new_house_model.objects.filter(addr1__icontains=search)
                    res5 = TES_submit_new_house_model.objects.filter(addr2__icontains=search)
                    serializer1 = TES_submit_new_house_serializer2(res1, many=True)
                    serializer2 = TES_submit_new_house_serializer2(res2, many=True)
                    serializer3 = TES_submit_new_house_serializer2(res3, many=True)
                    serializer4 = TES_submit_new_house_serializer2(res4, many=True)
                    serializer5 = TES_submit_new_house_serializer2(res5, many=True)
                    l = serializer1.data+serializer2.data+serializer3.data+serializer4.data+serializer5.data
                    if l or search == "":
                         res = []
                         [res.append(x) for x in l if x not in res]
                    # print(res)
                    houses_data = TES_submit_new_house_model.objects.all()
                    serializer6 = TES_submit_new_house_serializer2(houses_data, many=True)
                    dictrec = {**{"total_pages": math.ceil(len(serializer6.data)/10)},**{"records":[]}}
                    try:
                    # while True:
                         paginator = CustomPagination()
                         paginator.page_size = 10
                         queryset = TES_submit_new_house_model.objects.all()
                         # result_page = paginator.paginate_queryset(queryset, request)
                         # print(result_page)
                         result_page = paginator.paginate_queryset(queryset, request)
                         serializer = TES_submit_new_house_serializer2(result_page, many=True)
                         # print(serializer.data[1])
                         if search == "":
                              return paginator.get_paginated_response(serializer.data)
                         elif search != "":
                              sumres = res+serializer.data
                              print(sumres)
                              finalres = []
                              [finalres.append(x) for x in res if x in sumres]
                              return paginator.get_paginated_response(finalres)
                         # return paginator.get_paginated_response(result_page)
                    except:
                         return JsonResponse({
                              "success":False,
                              "data":dictrec,
                              "message":"Invalid page"})
               except:
                    return JsonResponse({
                         "success":False,
                         "data":"",
                         "message":"missing parameter"
                    })
          except:
               return JsonResponse({
                         "success":False,
                         "data":"",
                         "message":"not admin"})
     except:
          return JsonResponse({
                         "success":False,
                         "data":"",
                         "message":"invalid token"})

@csrf_exempt
def get_all_visits(request):
     try:
          token = request.META.get('HTTP_AUTHORIZATION')
          list = token.split()
          key = list[1]
          key_list = key.split(".")
          payload_str = key_list[1]
          payload = base64url_decode(payload_str)
          payload_data = payload.decode('UTF-8')
          payload_data_parse = json.loads(payload_data)
          user_id = payload_data_parse["user_id"]
          try:
          # while True:
               get_superadmin = TES_superadmin.objects.get(id=ObjectId(user_id))
               try:
               # while True:
                    data = json.loads(request.body)
                    search = data["search"]
                    # if search == "":
                    #      all_visits = TES_house_visits_model.objects.all()
                    #      serializer = TES_house_visit_serializer(all_visits, many=True)
                    #      # serializer2 = TES_house_visit_serializer(all_visits, many=True)
                    #      if len(serializer.data) != 0:
                    #           l = []
                    #           for i in range(len(serializer.data)):
                    #                l.append({
                    #                     **serializer.data[i],
                    #                     **{"current_status":json.loads(serializer.data[i]["current_status"])}
                    #                })
                    #           return JsonResponse({
                    #           "success":True,
                    #           "data":l,
                    #           "message":"list of all visits"
                    #      })
                    # elif search != "":
                    # while True:
                    res1 = TES_house_visits_model.objects.filter(house_id__icontains = search)
                    res2 = TES_house_visits_model.objects.filter(customer_id__icontains = search)
                    res3 = TES_house_visits_model.objects.filter(report_template__icontains = search)
                    res4 = TES_house_visits_model.objects.filter(report_status__icontains = search)
                         # res5 = TES_house_visits_model.objects.filter(current_status__icontains = search)
                    l1 = []
                    l2 = []
                    l3 = []
                    l4 = []
                         # l5 = []
                    ser1 = TES_house_visit_serializer(res1, many=True)
                         # ser11 = TES_house_visit_serializer(res1, many=True)
                    if len(ser1.data) != 0:
                              for i in range(len(ser1.data)):
                                   l1.append({
                                        **ser1.data[i],
                                        **{"current_status":json.loads(ser1.data[i]["current_status"])}
                                   })
                    # print(ser1.data[i]["current_status"][i].items())
                    for i in l1:
                         x = i.items()
                    y = tuple(x)
                    # print(y[5][1])
                    n = []
                    for i in y[5][1]:
                         g = i.items()
                    q = tuple(g)
                    print(q[2])
                    if q[2][1] == "pending":
                    # if q[2][1] == search:
                         print(l1)
                    ser2 = TES_house_visit_serializer(res2, many=True)
                         # ser21 = TES_house_visit_serializer(res2, many=True)
                    if len(ser2.data) != 0:
                              for i in range(len(ser2.data)):
                                   l2.append({
                                        **ser2.data[i],
                                        **{"current_status":json.loads(ser2.data[i]["current_status"])}
                                   })
                    ser3 = TES_house_visit_serializer(res3, many=True)
                         # ser31 = TES_house_visit_serializer(res3, many=True)
                    if len(ser3.data) != 0:
                              for i in range(len(ser3.data)):
                                   l3.append({
                                        **ser3.data[i],
                                        **{"current_status":json.loads(ser3.data[i]["current_status"])}
                                   })
                    ser4 = TES_house_visit_serializer(res4, many=True)
                         # ser41 = TES_house_visit_serializer(res4, many=True)
                    if len(ser4.data) != 0:
                              for i in range(len(ser4.data)):
                                   l4.append({
                                        **ser4.data[i],
                                        **{"current_status":json.loads(ser4.data[i]["current_status"])}
                                   })
                         # ser5 = TES_house_visits_serializer(res5, many=True)
                         # ser51 = TES_house_visit_serializer(res5, many=True)
                         # if len(ser5.data) != 0:
                         #      for i in range(len(ser5.data)):
                         #           l5.append({
                         #                **ser5.data[i],
                         #                **{"current_status":json.loads(ser51.data[i]["current_status"])}
                         #           })
                    l = l1 + l2 + l3 + l4
                         # l = l5
                    if l or search == "":
                              res = []
                              [res.append(x) for x in l if x not in res]
                              return JsonResponse({
                                   "success":True,
                                   "data":res,
                                   "message": f"search result of {search}"
                    })
                    else:
                         return JsonResponse({
                         "success":False,
                         "data":"",
                         "message": "search result not found"
                    })
               except:
               # while True:
                    all_visits = TES_house_visits_model.objects.all()
                    serializer = TES_house_visit_serializer(all_visits, many=True)
                    # serializer2 = TES_house_visit_serializer(all_visits, many=True)
                    if len(serializer.data) != 0:
                         l = []
                         for i in range(len(serializer.data)):
                              l.append({
                                        **serializer.data[i],
                                        **{"current_status":json.loads(serializer.data[i]["current_status"])}
                                   })
                         # print(serializer.data[0]["current_status"])
                         return JsonResponse({
                              "success":True,
                              "data":l,
                              "message":"list of all visits"
                         })
          except BaseException:
               return JsonResponse({
               "success":False,
               "data":"",
               "message":"not admin"
          })
     except BaseException:
             return JsonResponse({
               "success":False,
               "data":"",
               "message":"Invalid token"
          })
     
@csrf_exempt
def get_all_reports(request):
     try:
          token = request.META.get('HTTP_AUTHORIZATION')
          list = token.split()
          key = list[1]
          key_list = key.split(".")
          payload_str = key_list[1]
          payload = base64url_decode(payload_str)
          payload_data = payload.decode('UTF-8')
          payload_data_parse = json.loads(payload_data)
          user_id = payload_data_parse["user_id"]
          try:
               get_superadmin = TES_superadmin.objects.get(id=ObjectId(user_id))
               all_reports = TES_report_model.objects.all()
               serializer = TES_report_serializer2(all_reports, many=True)
               return JsonResponse({
               "success":True,
               "data":serializer.data,
               "message":"list of all reports"
              })
          except BaseException:
               return JsonResponse({
               "success":False,
               "data":"",
               "message":"not admin"
          })
     except BaseException:
             return JsonResponse({
               "success":False,
               "data":"",
               "message":"Invalid token"
          })
     
@csrf_exempt
def get_all_templates(request):
     try:
          token = request.META.get('HTTP_AUTHORIZATION')
          list = token.split()
          key = list[1]
          key_list = key.split(".")
          payload_str = key_list[1]
          payload = base64url_decode(payload_str)
          payload_data = payload.decode('UTF-8')
          payload_data_parse = json.loads(payload_data)
          user_id = payload_data_parse["user_id"]
          try:
               get_superadmin = TES_superadmin.objects.get(id=ObjectId(user_id))
               all_reports = TES_template_model.objects.all()
               serializer = TES_template_serializer2(all_reports, many=True)
               return JsonResponse({
               "success":True,
               "data":serializer.data,
               "message":"list of all templates"
              })
          except BaseException:
               return JsonResponse({
               "success":False,
               "data":"",
               "message":"not admin"
          })
     except BaseException:
             return JsonResponse({
               "success":False,
               "data":"",
               "message":"Invalid token"
          })

@csrf_exempt
def delete_user(request):
     try:
          token = request.META.get('HTTP_AUTHORIZATION')
          list = token.split()
          key = list[1]
          key_list = key.split(".")
          payload_str = key_list[1]
          payload = base64url_decode(payload_str)
          payload_data = payload.decode('UTF-8')
          payload_data_parse = json.loads(payload_data)
          user_id = payload_data_parse["user_id"]
          data = json.loads(request.body)
          particular_id = data["id"]
          try:
               get_superadmin = TES_superadmin.objects.get(id=ObjectId(user_id))
               try:
                    get_user = TES_new_Model.objects.get(id=ObjectId(particular_id))
                    get_user.delete()
                    return JsonResponse({
                          "success":True,
                          "data":"",
                          "message":f"user {particular_id} deleted"
                         })
               except BaseException:
                    return JsonResponse({
                          "success":False,
                          "data":"",
                          "message":"user doesn't exist"
                         })
          except BaseException:
               return JsonResponse({
               "success":False,
               "data":"",
               "message":"not admin"
          })
     except BaseException:
             return JsonResponse({
               "success":False,
               "data":"",
               "message":"Invalid token"
          })

@csrf_exempt
def delete_house(request):
     try:
          token = request.META.get('HTTP_AUTHORIZATION')
          list = token.split()
          key = list[1]
          key_list = key.split(".")
          payload_str = key_list[1]
          payload = base64url_decode(payload_str)
          payload_data = payload.decode('UTF-8')
          payload_data_parse = json.loads(payload_data)
          user_id = payload_data_parse["user_id"]
          data = json.loads(request.body)
          particular_id = data["id"]
          try:
               get_superadmin = TES_superadmin.objects.get(id=ObjectId(user_id))
               try:
                    get_house = TES_submit_new_house_model.objects.get(id=ObjectId(particular_id))
                    get_house.delete()
                    return JsonResponse({
                          "success":True,
                          "data":"",
                          "message":f"house {particular_id} deleted"
                         })
               except BaseException:
                    return JsonResponse({
                          "success":False,
                          "data":"",
                          "message":"house doesn't exist"
                         })
          except BaseException:
               return JsonResponse({
               "success":False,
               "data":"",
               "message":"not admin"
          })
     except BaseException:
             return JsonResponse({
               "success":False,
               "data":"",
               "message":"Invalid token"
          })
     
@csrf_exempt
def delete_visit(request):
     try:
          token = request.META.get('HTTP_AUTHORIZATION')
          list = token.split()
          key = list[1]
          key_list = key.split(".")
          payload_str = key_list[1]
          payload = base64url_decode(payload_str)
          payload_data = payload.decode('UTF-8')
          payload_data_parse = json.loads(payload_data)
          user_id = payload_data_parse["user_id"]
          data = json.loads(request.body)
          particular_id = data["id"]
          try:
               get_superadmin = TES_superadmin.objects.get(id=ObjectId(user_id))
               try:
                    get_visit = TES_house_visits_model.objects.get(id=ObjectId(particular_id))
                    get_visit.delete()
                    return JsonResponse({
                          "success":True,
                          "data":"",
                          "message":f"visit {particular_id} deleted"
                         })
               except BaseException:
                    return JsonResponse({
                          "success":False,
                          "data":"",
                          "message":"visit doesn't exist"
                         })
          except BaseException:
               return JsonResponse({
               "success":False,
               "data":"",
               "message":"not admin"
          })
     except BaseException:
             return JsonResponse({
               "success":False,
               "data":"",
               "message":"Invalid token"
          })

@csrf_exempt
def delete_report(request):
     try:
          token = request.META.get('HTTP_AUTHORIZATION')
          list = token.split()
          key = list[1]
          key_list = key.split(".")
          payload_str = key_list[1]
          payload = base64url_decode(payload_str)
          payload_data = payload.decode('UTF-8')
          payload_data_parse = json.loads(payload_data)
          user_id = payload_data_parse["user_id"]
          data = json.loads(request.body)
          particular_id = data["id"]
          try:
               get_superadmin = TES_superadmin.objects.get(id=ObjectId(user_id))
               try:
                    get_visit = TES_report_model.objects.get(_id=ObjectId(particular_id))
                    get_visit.delete()
                    return JsonResponse({
                          "success":True,
                          "data":"",
                          "message":f"report {particular_id} deleted"
                         })
               except BaseException:
                    return JsonResponse({
                          "success":False,
                          "data":"",
                          "message":"report doesn't exist"
                         })
          except BaseException:
               return JsonResponse({
               "success":False,
               "data":"",
               "message":"not admin"
          })
     except BaseException:
             return JsonResponse({
               "success":False,
               "data":"",
               "message":"Invalid token"
          })
     
@csrf_exempt
def delete_template(request):
     try:
          token = request.META.get('HTTP_AUTHORIZATION')
          list = token.split()
          key = list[1]
          key_list = key.split(".")
          payload_str = key_list[1]
          payload = base64url_decode(payload_str)
          payload_data = payload.decode('UTF-8')
          payload_data_parse = json.loads(payload_data)
          user_id = payload_data_parse["user_id"]
          data = json.loads(request.body)
          particular_id = data["id"]
          try:
               get_superadmin = TES_superadmin.objects.get(id=ObjectId(user_id))
               try:
                    get_visit = TES_template_model.objects.get(id=ObjectId(particular_id))
                    get_visit.delete()
                    return JsonResponse({
                          "success":True,
                          "data":"",
                          "message":f"template {particular_id} deleted"
                         })
               except BaseException:
                    return JsonResponse({
                          "success":False,
                          "data":"",
                          "message":"template doesn't exist"
                         })
          except BaseException:
               return JsonResponse({
               "success":False,
               "data":"",
               "message":"not admin"
          })
     except BaseException:
             return JsonResponse({
               "success":False,
               "data":"",
               "message":"Invalid token"
          })

@csrf_exempt
def edit_user(request):
     try:
          token = request.META.get('HTTP_AUTHORIZATION')
          list = token.split()
          key = list[1]
          key_list = key.split(".")
          payload_str = key_list[1]
          payload = base64url_decode(payload_str)
          payload_data = payload.decode('UTF-8')
          payload_data_parse = json.loads(payload_data)
          user_id = payload_data_parse["user_id"]
          try:
               get_superadmin = TES_superadmin.objects.get(id=ObjectId(user_id))
               try:
                    data = json.loads(request.body)
                    particular_id = data["id"]
                    e_v = data["email"]
                    n_v = data["name"]
                    a_v = data["addr"]
                    try:
                         get_visit = TES_new_Model.objects.filter(id=ObjectId(particular_id)).update(email=e_v, name=n_v, addr=a_v)
                         # get_user = TES_new_Model.objects.get(id=ObjectId(particular_id))
                         # get_user.email = e_v
                         # get_user.name = n_v
                         # get_user.addr = a_v
                         # get_user.save(update_fields=["email", "name", "addr"])
                         return JsonResponse({
                          "success":True,
                          "data":"",
                          "message":f"user {particular_id} updated from admin side"
                         })
                    except BaseException:
                         return JsonResponse({
                          "success":False,
                          "data":"",
                          "message":"user doesn't exist"
                         })
               except BaseException:
                    return JsonResponse({
                          "success":False,
                          "data":"",
                          "message":"please give all fields"
                         })
          except BaseException:
               return JsonResponse({
               "success":False,
               "data":"",
               "message":"not admin"
          })
     except BaseException:
             return JsonResponse({
               "success":False,
               "data":"",
               "message":"Invalid token"
          })

@csrf_exempt
def edit_house(request):
     try:
          token = request.META.get('HTTP_AUTHORIZATION')
          list = token.split()
          key = list[1]
          key_list = key.split(".")
          payload_str = key_list[1]
          payload = base64url_decode(payload_str)
          payload_data = payload.decode('UTF-8')
          payload_data_parse = json.loads(payload_data)
          user_id = payload_data_parse["user_id"]
          try:
               get_superadmin = TES_superadmin.objects.get(id=ObjectId(user_id))
               try:
                    data = json.loads(request.body)
                    particular_id = data["id"]
                    h_v = data["house_id"]
                    a1_v = data["addr1"]
                    a2_v = data["addr2"]
                    p_v = data["phone"]
                    try:
                         get_user_id = TES_submit_new_house_model.objects.get(id=ObjectId(particular_id))
                         cid = get_user_id.customer_id
                         try:
                              get_user = TES_new_Model.objects.get(id=ObjectId(cid))
                              try:
                                   get_visit = TES_submit_new_house_model.objects.filter(id=ObjectId(particular_id)).update(house_id=h_v, addr1=a1_v, addr2=a2_v, phone=p_v)
                                   return JsonResponse({
                                      "success":True,
                                      "data":"",
                                      "message":f"house {particular_id} updated from admin side"
                                   })
                              except BaseException:
                                   return JsonResponse({
                                      "success":False,
                                      "data":"",
                                      "message":"house with this id doesn't exist"
                                   })
                         except BaseException:
                                   return JsonResponse({
                                      "success":False,
                                      "data":"",
                                      "message":"user is not registered    "
                                   })
                    except BaseException:
                         return JsonResponse({
                                  "success":False,
                                  "data":"",
                                  "message":"house with this id doesn't exist"
                              })
               except BaseException:
                    return JsonResponse({
                          "success":False,
                          "data":"",
                          "message":"all fields not given"
                         })
          except BaseException:
               return JsonResponse({
               "success":False,
               "data":"",
               "message":"not admin"
          })
     except BaseException:
             return JsonResponse({
               "success":False,
               "data":"",
               "message":"Invalid token"
          })

@csrf_exempt
def edit_report(request):
     try:
          token = request.META.get('HTTP_AUTHORIZATION')
          list = token.split()
          key = list[1]
          key_list = key.split(".")
          payload_str = key_list[1]
          payload = base64url_decode(payload_str)
          payload_data = payload.decode('UTF-8')
          payload_data_parse = json.loads(payload_data)
          user_id = payload_data_parse["user_id"]
          try:
               get_superadmin = TES_superadmin.objects.get(id=ObjectId(user_id))
               try:
                    data = json.loads(request.body)
                    particular_id = data["id"]
                    r_n = data["report_name"]
                    try:
                         get_report = TES_report_model.objects.filter(_id=ObjectId(particular_id)).update(report_name=r_n)
                         return JsonResponse({
                                      "success":True,
                                      "data":"",
                                      "message":f"report {particular_id} updated from admin side"
                                   })
                    except BaseException:
                         return JsonResponse({
                                  "success":False,
                                  "data":"",
                                  "message":"report with this id doesn't exist"
                              })
               except BaseException:
                    return JsonResponse({
                          "success":False,
                          "data":"",
                          "message":"all fields not given"
                         })
          except BaseException:
               return JsonResponse({
               "success":False,
               "data":"",
               "message":"not admin"
          })
     except BaseException:
             return JsonResponse({
               "success":False,
               "data":"",
               "message":"Invalid token"
          })
     
@csrf_exempt
def edit_visit(request):
     try:
          token = request.META.get('HTTP_AUTHORIZATION')
          list = token.split()
          key = list[1]
          key_list = key.split(".")
          payload_str = key_list[1]
          payload = base64url_decode(payload_str)
          payload_data = payload.decode('UTF-8')
          payload_data_parse = json.loads(payload_data)
          user_id = payload_data_parse["user_id"]
          try:
               get_superadmin = TES_superadmin.objects.get(id=ObjectId(user_id))
               try:
                    data = json.loads(request.body)
                    particular_id = data["id"]  #visit_id
                    house_id = data["house_id"] 
                    report_status = data["report_status"]
                    report_id = data["report_id"]
                    try:
                         get_particular_visit = TES_house_visits_model.objects.get(id=ObjectId(particular_id))
                         try:
                              get_customer_id = get_particular_visit.customer_id
                              get_customer = TES_new_Model.objects.get(id=ObjectId(get_customer_id))
                              try:
                                   serializer = TES_house_visit_serializer(get_particular_visit)
                                   update = serializer.data["current_status"]
                                   update_json = json.loads(update)
                                   for i in range(len(update_json)):
                                        if update_json[i]["report_id"] == report_id:
                                             i_v = i
                                   update_status = update_json[i_v]["status"]
                                   update_status = update_status.replace("pending","completed")
                                   t = tuple(zip(update_json[i_v].keys(), update_json[i_v].values()))
                                   dict_t = dict(t)
                                   dict_t["status"] = update_status
                                   k = update_json[i_v]
                                   l = dict_t
                                   r = k.update(l)
                                   get_particular_visit.current_status[i_v].update(k)
                                   get_particular_visit.house_id = house_id
                                   get_particular_visit.report_status = report_status
                                   get_particular_visit.save()
                                   serializer = TES_house_visit_serializer(get_particular_visit)
                                   return JsonResponse({
                                      "success":True,
                                      "data":"",
                                      "message":f"visit {particular_id} updated from admin side"
                                   })
                              except BaseException:
                                   return JsonResponse({
                                      "success":False,
                                      "data":"",
                                      "message":"visit can't be updated"
                                   })
                         except BaseException:
                              return JsonResponse({
                                  "success":False,
                                  "data":"",
                                  "message":"customer is not registered"
                                   })
                    except BaseException:
                         return JsonResponse({
                                  "success":False,
                                  "data":"",
                                  "message":"Invalid visit id"
                              })
               except BaseException:
                    return JsonResponse({
                          "success":False,
                          "data":"",
                          "message":"all fields not given"
                         })
          except BaseException:
               return JsonResponse({
               "success":False,
               "data":"",
               "message":"not admin"
          })
     except BaseException:
             return JsonResponse({
               "success":False,
               "data":"",
               "message":"Invalid token"
          })

@csrf_exempt
def edit_template(request):
     try:
          token = request.META.get('HTTP_AUTHORIZATION')
          list = token.split()
          key = list[1]
          key_list = key.split(".")
          payload_str = key_list[1]
          payload = base64url_decode(payload_str)
          payload_data = payload.decode('UTF-8')
          payload_data_parse = json.loads(payload_data)
          user_id = payload_data_parse["user_id"]
          try:
               get_superadmin = TES_superadmin.objects.get(id=ObjectId(user_id))
               try:
                    data = json.loads(request.body)
                    particular_id = data["id"]
                    t_n = data["template_name"]
                    try:
                         get_template = TES_template_model.objects.filter(id=ObjectId(particular_id)).update(template_name=t_n)
                         return JsonResponse({
                                      "success":True,
                                      "data":"",
                                      "message":f"template {particular_id} updated from admin side"
                                   })
                    except BaseException:
                         return JsonResponse({
                                  "success":False,
                                  "data":"",
                                  "message":"template with this id doesn't exist"
                              })
               except BaseException:
                    return JsonResponse({
                          "success":False,
                          "data":"",
                          "message":"all fields not given"
                         })
          except BaseException:
               return JsonResponse({
               "success":False,
               "data":"",
               "message":"not admin"
          })
     except BaseException:
             return JsonResponse({
               "success":False,
               "data":"",
               "message":"Invalid token"
          })
     
