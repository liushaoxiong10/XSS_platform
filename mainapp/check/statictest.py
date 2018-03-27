import MySQLdb
import os
import magic
import re

output_string = "print|print_r|echo|printf|sprintf|die|var_dump|var_export"
filter_string = "filter_var|mysql_real_escape_string|htmlentities|htmlspecialchars|strip_tags"
report = ""
cmd5 = ""
variate = {}


def have_variate(line):
    line = line[:-1]
    remt = re.match("\$(.*?)=", line.strip())
    try:
        key = line.strip()[remt.span()[0]:remt.span()[1] - 1].strip()
        if remt and key not in variate.keys():
            variate[key] = line.strip()[remt.span()[1]:].strip()
        elif remt and key in variate.keys() and line.strip()[remt.span()[1:]] not in variate[key]:
            variate[key] = variate[key] + ";" + line.strip()[remt.span()[1:]].strip()
        else:
            pass
    except:
        pass


def trace_source(val):
    ret = ""
    for i in re.finditer('\$', val):
        val_match_val = val[i.span()[1]:i.span()[1] + 1]
        for k in sorted(list(variate.keys()), key=len, reverse=True):
            if re.match('\$' + val_match_val, k) and val[i.span()[0]:(i.span()[0] + len(k))] == k:
                ret += variate[k]
                if '$' in variate[k] and '$_GET' not in variate[k] and '$_POST' not in variate[k]:
                    ret += trace_source(variate[k]) + ";"

                break
    return ret


def php_static_check(filepath):
    with open(filepath, "r") as f:
        filestr = f.readlines()
    global report
    have = True
    global variate
    variate = {}

    for i in range(len(filestr)):
        if re.match(output_string, filestr[i].strip()):
            if '$_GET' in filestr[i] or '$_POST' in filestr[i]:
                if re.findall(filter_string, filestr[i]):
                    report += '<p class="font-bold"> Line ' + str(i + 1) + '<span class="col-orange">' + \
                              filestr[i].replace("<", "<span><</span>") + '</span> 输出存在变量，但已过滤，可能会造成XSS</p>'
                else:
                    report += '<p class="font-bold"> Line ' + str(i + 1) + '<span class="col-orange">' + \
                              filestr[i].replace("<", "<span><</span>") + '</span> 输出存在变量，且没有过滤，可能会造成XSS</p>'
                have = False
            elif "$" in filestr[i]:
                if not re.findall(filter_string, filestr[i]):
                    for j in re.finditer('\$', filestr[i]):
                        symbol = filestr[i][j.span()[0] - 1:j.span()[0]]
                        var = "$"
                        if symbol == '(':
                            symbol = ')'
                        local = j.span()[0] + 1
                        while var[-1] != symbol:
                            var += filestr[i][local:local + 1]
                            local += 1
                        var = var[:-1]
                        val = variate[var]

                        if '$_GET' in val or '$_POST' in val:
                            if re.findall(filter_string, val):
                                report += '<p class="font-bold"> Line ' + str(i + 1) + '<span class="col-orange">' + \
                                          filestr[i].replace("<", "<span><</span>") + '</span> 输出存在变量，但已过滤，可能会造成XSS</p>'
                            else:
                                report += '<p class="font-bold"> Line ' + str(i + 1) + '<span class="col-orange">' + \
                                          filestr[i].replace("<",
                                                             "<span><</span>") + '</span> 输出存在变量，且没有过滤，可能会造成XSS</p>'
                            have = False
                        elif '$' in val:
                            variate[var] += ";" + trace_source(val)
                            val = variate[var]

                            if '$_GET' in val or '$_POST' in val:
                                if re.findall(filter_string, val):
                                    report += '<p class="font-bold"> Line ' + str(i + 1) + '<span class="col-orange">' + \
                                              filestr[i].replace("<",
                                                                 "<span><</span>") + '</span> 输出存在变量，但已过滤，可能会造成XSS</p>'
                                else:
                                    report += '<p class="font-bold"> Line ' + str(i + 1) + '<span class="col-orange">' + \
                                              filestr[i].replace("<",
                                                                 "<span><</span>") + '</span> 输出存在变量，且没有过滤，可能会造成XSS</p>'

                        else:
                            pass
                else:
                    report += '<p class="font-bold"> Line ' + str(i + 1) + '<span class="col-orange">' + \
                              filestr[i].replace("<", "<span><</span>") + '</span> 输出存在变量，但已过滤，可能会造成XSS</p>'

        elif "$" in filestr[i]:
            have_variate(filestr[i])
        else:
            pass
    if have:
        report += '<p class="font-bold"> Not Find </p>'


def php_start(name, filepath, filetype):
    global report
    report += '<p class="font-bold">Name:' + name + '</p><p class="font-bold">File Type:' + filetype + '</p>'
    php_static_check(filepath)


def zip_start(unzip_dir):
    file_list = []
    for root, dirs, files in os.walk(unzip_dir):
        for f in files:
            file_list.append(os.path.join(root, f))
    for file in file_list:
        filetype = magic.Magic().from_file(file)
        if "PHP" in filetype or "php" in os.path.split(file)[1].lower().split(".")[-1]:
            php_start(file.split("Unzip")[1], file, filetype)
            global variate
            variate = {}
        else:
            pass


def report_save():
    global cmd5, report
    conn = MySQLdb.connect(host='127.0.0.1', user='root', passwd='liushaoxiong', db='xss_info', charset="utf8")
    cur = conn.cursor()
    cur.execute('insert into mainapp_history(conmd5,report) values(%s,%s)', (cmd5, report))
    conn.commit()
    cur.close()
    conn.close()
    quit()


def statictest(name, filepath, conmd5, filetype):
    global cmd5
    cmd5 = conmd5
    if "PHP" in filetype or "php" in name.split(".")[-1]:
        php_start(name, filepath, filetype)
        report_save()
    elif "Zip" in filetype:
        import zipfile
        zip_file = zipfile.ZipFile(filepath)
        unzip_dir = os.path.join(os.path.dirname(filepath), "Unzip")
        os.makedirs(unzip_dir)
        for n in zip_file.namelist():
            zip_file.extract(n, unzip_dir)
        zip_file.close()
        try:
            zip_start(unzip_dir)
        except Exception as e:
            global report
            report += "<h1>" + e + "<h1>"
        report_save()

    else:
        print(filetype)
        quit()
