import urllib
from urllib.parse import unquote

import requests
import json
from urllib import parse
from urllib import request
import time,httplib2

def get_url():

    headers = {
        'Host': '866.ebanktest.com.cn:3866',
        'Connection': 'close',
        'Content-Length': '598',
        'rqId': 'A1',
        'global_path_num': '1',
        'ser-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36',
        'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'global_trace_num': '00000060000010a14fa9363e212da0cca6d41f51630f7',
        'bkId': '866',
        'X-Requested-With': 'XMLHttpRequest',
        'opId': 'ebus_functionSearch',
        'transId': '400000000',
        'Origin': 'https://866.ebanktest.com.cn:3866',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Referer': 'https://866.ebanktest.com.cn:3866/pbank/',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Cookie': 'SESSION=15bc8d69-0aac-4568-8ba1-724f0dfb40f4; grayRoutePB=all; backpb=iboc_pbank1; equipmentID=1b4cae5fcba52d0aaead73464890e3b09a81efd708ea7d6d49c9e00a555cb23f; unloadTime=1599101884432; routePB=9b8b01f518dd2ec29cc3c87941a52293|1599102229|1599102009'

    }
    # f = open("zxc.txt")  # 返回一个文件对象
    # line = f.readline()  # 调用文件的 readline()方法
    # while line:
    #     print (line),  # 后面跟 ',' 将忽略换行符
    #     # print(line, end = '')　      # 在 Python 3 中使用
    #     line = f.readline()
    for line in open("zxc.txt"):
        newline=line.strip()
        param = (
            '%7B%22reqData%22%3A%7B%22queryFlag%22%3A%220%22%2C%22bdfName%22%3A%22{}%22%2C%22turnPageBeginPos%22%3A1%2C%22turnPageShowNum%22%3A%2210%22%2C%22turnPageValue%22%3A%221%7C%7C10%22%2C%22turnPageFlag%22%3A%220%22%7D%2C%22reqHead%22%3A%7B%22rqId%22%3A%22A1%22%2C%22referer%22%3A%22https%3A%2F%2F866.ebanktest.com.cn%3A3866%2Fpbank%2F%23%2Findex%2Fsearch%22%2C%22sn%22%3Anull%2C%22transId%22%3A%22490000000%22%2C%22bkId%22%3A%22866%22%2C%22stime%22%3A%2220200903112012352%22%2C%22sid%22%3Anull%2C%22rspFmt%22%3A%22json%22%2C%22submitKey%22%3Anull%2C%22version_num%22%3A%22PB_V4%22%2C%22appVer%22%3A%22chrome%2F85.0.4183.83%22%2C%22dNo%22%3A%221b4cae5fcba52d0aaead73464890e3b09a81efd708ea7d6d49c9e00a555cb23f%22%2C%22isPassword%22%3Atrue%2C%22flag%22%3Atrue%2C%22opId%22%3A%22ebus_functionSearch%22%7D%2C%22mac%22%3A%225SGGRu1K2JZaHpRZH%3CioZQ%3CAZsTomGeZuqjek3ZHI4o%3D%22%7D').format(
            newline)
        data = {
            'rqId': 'A1',
            'jsonData': param
        }
        proxies = {
            "http": "127.0.0.1:8080", "https": "127.0.0.1:8080"
        }
        target_url = "https://866.ebanktest.com.cn:3866/pbank/ebus_CstCommonsAdvice.do"

        name = parse.urlencode(data)
        url_org = parse.unquote(name)
        print(url_org)
        res = requests.post(target_url, headers=headers, data=url_org, proxies=proxies)



def main():
    get_url()

if __name__ == "__main__":
    main()