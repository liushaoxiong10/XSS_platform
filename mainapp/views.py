from django.shortcuts import render
from django.http import HttpResponse
from django.views.generic import View

from hashlib import md5
import time
from multiprocessing import Process
from magic import Magic
import os

from .models import StaticInfo, DynamicInfo, History
from mainapp.check.dymictest import initator
from mainapp.check.statictest import statictest


class Index_view(View):
    def get(self, request):
        static_obj = StaticInfo.objects.all()
        dynamic_obj = DynamicInfo.objects.all()
        history_obj = History.objects.all()
        static_count = len(static_obj)
        dynamic_count = len(dynamic_obj)
        all_count = static_count + dynamic_count
        history_count = len(history_obj)
        now_count = all_count - history_count
        if now_count == 0:
            return render(request, 'index.html', {"all_count":all_count, "now_count":now_count, "static_count":static_count, "dynamic_count":dynamic_count })
        else:
            now_obj_cmd5 = []
            static_obj_cmd5 = []
            dynamic_obj_cm5 = []
            history_obj_cmd5 = []
            for i in static_obj:
                static_obj_cmd5.append(i.conmd5)
            for i in dynamic_obj:
                dynamic_obj_cm5.append(i.conmd5)
            for i in history_obj:
                history_obj_cmd5.append(i.conmd5)
            for i in (static_obj_cmd5 + dynamic_obj_cm5):
                if i not in history_obj_cmd5:
                    now_obj_cmd5.append(i)
            now_task = []
            for i in now_obj_cmd5:
                try:
                    task = dynamic_obj.filter(conmd5=i)[0]
                    now_task.append({"Method": "Dynamic", "Message": task.url})
                except:
                    task = static_obj.filter(conmd5=i)[0]
                    now_task.append({"Method":"Static","Message": task.name})
            for i in range(len(now_task)):
                now_task[i]["id"] = str(i+1)
            return render(request, 'index.html', {"all_count":all_count, "now_count":now_count, "static_count":static_count, "dynamic_count":dynamic_count, "now_task":now_task })



class DynamicTest_view(View):
    def get(self, request):
        return render(request, 'dynamic_test.html')

    def post(self, request):
        try:
            info = request.POST
            url = info['url']
            method = info['method']
            cookies = info['cookies']
            args = info['args']
            param = info['param']
            delay = info['delay']
            conmd5 = md5()
            conmd5.update((url + args + str(time.time())).encode("utf-8"))
            conmd5 = conmd5.hexdigest()
            DynamicInfo.objects.create(url=url, method=method, cookies=cookies, args=args, param=param, conmd5=conmd5)
            # p = Process(target=saveReport, args=(url, method, args, param, delay, cookies, conmd5))
            p = Process(target=initator, args=(url, method, args, param, delay, cookies, conmd5))
            p.daemon = True
            p.start()
            return HttpResponse("success")
        except:
            return HttpResponse("error")


class StaticTest_view(View):
    def get(self, request):
        return render(request, 'static_test.html')

    # 文件上传
    def post(self, request):
        file = request.FILES
        status = saveUploadFile(file)
        if (status != "success"):
            return HttpResponse("ERROR" + status)
        returnmess = ""
        for i in file:
            returnmess += str(file[i])
        return HttpResponse(returnmess)


#
# class StaticTest_UploadFile_view(View):
#     def get(self, request):
#         return render(request, 'static_test/upload_file.html')
#
#     # 文件上传
#     def post(self, request):
#         file = request.FILES
#         status = saveUploadFile(file)
#         if (status != "success"):
#             return HttpResponse("ERROR" + status)
#         returnmess = ""
#         for i in file:
#             returnmess += str(file[i])
#         return HttpResponse(returnmess)
# class StaticTest_Input_view(View):
#     def get(self, request):
#         return render(request, 'static_test/input_online.html')
#     def post(self, request):
#         print(request.POST['value'])
#
#         return HttpResponse("success")



class History_view(View):
    def get(self, request):
        dynamic = DynamicInfo.objects.all()
        dynamic_info = []
        for i in dynamic:
            idict = {}
            idict["url"] = i.url
            idict["method"] = i.method
            idict["param"] = i.args
            idict["cookies"] = i.cookies
            idict["date"] = i.date
            idict["report"] = i.conmd5
            dynamic_info.append(idict)
        static = StaticInfo.objects.all()
        static_info = []
        for i in static:
            idict={}
            idict["name"] = i.name
            idict["date"] = i.date
            idict["fileType"] = i.fileType
            idict["report"] = i.conmd5
            static_info.append(idict)

        return render(request, 'history.html',{'dynamic_info':dynamic_info, 'static_info':static_info})

class GetReport_view(View):
    def get(self, request):

        conmd5 = request.GET.get('conmd5')
        try:
            data = History.objects.filter(conmd5=conmd5)
            return HttpResponse(data[0].report)
        except:
            return HttpResponse("<h1>PLEASE WAIT!!!</h1>")

def temp(request):
    return render(request, 'temp.html')


# 保存上传文件
def saveUploadFile(file):
    try:
        dir_path = os.path.join(os.getcwd(), 'media', time.strftime("%Y.%m.%d_%H.%M"))
        if not os.path.isdir(dir_path):
            os.makedirs(dir_path)
        for i in file:
            name = str(file[i])
            content = file[i].read()
            conmd5 = md5()
            conmd5.update(str(content).encode("utf-8") + str(time.time()).encode("utf-8"))
            conmd5 = conmd5.hexdigest()
            filetype = Magic().from_buffer(content)
            file_path = os.path.join(dir_path, name)
            with open(file_path, "wb") as f:
                f.write(content)
            StaticInfo.objects.create(name=name, file=file_path, conmd5=conmd5, fileType=filetype.split(",")[0])
            p = Process(target=statictest, args=(name, file_path, conmd5, filetype))
            p.daemon = True
            p.start()
        return "success"
    except Exception as e:
        return ("Error" + str(e))



