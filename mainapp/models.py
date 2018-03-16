from django.db import models
from datetime import datetime
# Create your models here.


class StaticInfo(models.Model):
    name = models.CharField(max_length=30, verbose_name=u"文件名", default=u"在线文档")
    date = models.DateTimeField(default=datetime.now, verbose_name=u"提交时间")
    file = models.FileField(upload_to="staticfile", verbose_name=u"文件", default='test/test.txt')
    conmd5 = models.CharField(max_length=255, verbose_name=u"文件MD5")
    fileType = models.CharField(max_length=20, verbose_name=u"文件类型")


class DynamicInfo(models.Model):
    url = models.TextField(verbose_name="URL")
    method = models.CharField(max_length=5, verbose_name="method", default="GET")
    args = models.TextField(verbose_name=u"参数")
    cookies = models.TextField(verbose_name=u"Cookies", default="")
    param = models.CharField(verbose_name=u"猜测参数", max_length=50, default="")
    conmd5 = models.CharField(max_length=255, verbose_name=u"文件MD5")
    date = models.DateTimeField(default=datetime.now, verbose_name=u"提交时间")



class History(models.Model):
    conmd5 = models.CharField(max_length=255, verbose_name=u"MD5值")
    report = models.TextField(verbose_name=u"报告内容")











