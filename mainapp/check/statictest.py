import MySQLdb
import os
import magic

output_string = ["print", "print_r", "echo", "printf", "sprintf", "die", "var_dump", "var_export"]
report = ""
cmd5 = ""


def php_static_check(filepath):
    with open(filepath, "r") as f:
        filestr = f.readlines()
    global report
    have = True

    for i in range(len(filestr)):
        for ou in output_string:
            if ou in filestr[i]:
                if '$_GET' in filestr[i] or '$_POST' in filestr[i]:
                    report += '<p class="font-bold"> Line ' + str(i + 1) + '<span class="col-orange">'+ filestr[i].replace("<", "<span><</span>") + '</span> 输出存在变量，可能会造成XSS</p>'
                    have = False
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
    if "PHP" in filetype  or "php" in name.split(".")[-1]:
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
        zip_start(unzip_dir)
        report_save()

    else:
        print(filetype)
        quit()
