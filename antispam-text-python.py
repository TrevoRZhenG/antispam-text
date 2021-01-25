# -*- coding:utf-8 -*-

import json
import base64
import hashlib
import argparse
from urllib import parse, request
from collections import OrderedDict


def predict(content, appid, appkey, textbizid, env="prod"):
    timestamp = 1531276098546
    outdataid = 2222222222
    data = {
        "appId": appid,
        "textBizId": textbizid,
        "outDataId": outdataid,
        "content": content.replace(' ', ''),
        "timestamp": timestamp,
    }
    sign = enc(data, appkey)
    data["sign"] = sign.decode('utf-8')

    if env == "prod":
        API = "https://antispam.wanmei.com/text/online/check"
    else:
        API = "http://antispam.wanmei.com/text/online/check"

    try:
        f = request.urlopen(API, parse.urlencode(data).encode('utf-8'))
        ret = f.read().decode('utf-8')
    except:
        print("check error......")
        return None, None, None, None

    obj = json.loads(ret)
    checkResult = obj['result']['checkResult']
    labels = list()
    details = list()
    if obj['result']['labels'] is not None:
        for label in obj['result']['labels']:
            labels.append(label['label'])
            if label['details'] is not None:
                details.append(label['details']['hint'])
    return ret, checkResult, labels, details, content


def enc(dic, appkey):
    encKey = appkey[2:5] + appkey[10:16] + appkey[18:20] + appkey[14:19]
    sorteded = OrderedDict(sorted(dic.items()))
    srcStr = parse.unquote(parse.urlencode(sorteded))
    conStr = (encKey + srcStr).encode('utf-8')
    return base64.b64encode(hashlib.sha256(conStr).digest())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(usage="input param.", description="antispam test demo")
    parser.add_argument("--env", choices=['prod', 'test'], default="online", help="the env type")
    parser.add_argument("--appId", default="", help="input appid.")
    parser.add_argument("--appKey", default="", help="input appkey.")
    parser.add_argument("--textBizId", default=1, help="input textbizid.")
    parser.add_argument("--content", default="", help="input content.")
    args = parser.parse_args()
    env = args.env
    appId = args.appId
    appkey = args.appKey
    textBizId = args.textBizId
    content = args.content

    ret, checkResult, labels, details, content = predict(content=content, appid=appId, appkey=appkey, textbizid=textBizId, env=env)
    # print(content)
    # print(checkResult)
    # print(labels)
    # print(details)
    print(ret)
