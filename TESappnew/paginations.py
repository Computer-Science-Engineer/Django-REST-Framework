from rest_framework.pagination import PageNumberPagination
from django.http import JsonResponse
from .models import TES_submit_new_house_model
from .serializers import TES_submit_new_house_serializer2
from collections import OrderedDict
import math


class CustomPagination(PageNumberPagination):
    page_size = 10
    # page_query_param = 'page'
    # def paginate_queryset(self, queryset, request, view=None):
    #     page_number = self.request.query_params.get(self.page_query_param, 1)
    def get_paginated_response(self, data):
        queryset = TES_submit_new_house_model.objects.all()
        serializer2  = TES_submit_new_house_serializer2(queryset, many=True)
        # page = CustomPagination.paginate_queryset(queryset, request)
        # i fpage is not None:
        return JsonResponse(OrderedDict([
             ('success', True),
          #   ('data', data ),
            ('data',{**{'total_pages': math.ceil(len(serializer2.data)/10)}, **{"records":data}}),
            ('message', 'all paginated records')
        ]))
        # else:
        #     return JsonResponse({
        #         "success":False
        #     })