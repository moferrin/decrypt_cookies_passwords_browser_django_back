from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from .utils import get_data

# Create your views here.
from django.http import JsonResponse

@csrf_exempt
def get_data_chrome(request):
    data = get_data(["Google","Chrome"])
    return JsonResponse(data)

@csrf_exempt
def get_data_brave(request):
    data = get_data(["BraveSoftware","Brave-Browser"])
    return JsonResponse(data)