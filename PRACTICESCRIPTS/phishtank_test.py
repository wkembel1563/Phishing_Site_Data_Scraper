#!/usr/bin/env python3

import requests
import base64
import xml.etree.ElementTree as ET


def encodePhishReqURL(uri):
    url = "http://checkurl.phishtank.com/checkurl/"
    new_check_bytes = uri.encode()
    base64_bytes = base64.b64encode(new_check_bytes)
    base64_new_check = base64_bytes.decode('ascii')
    url += base64_new_check
    return url


def queryPhishAPI(url):
    """This function sends a request."""
    key = '8a2c896086a34c5a7c5a076948679e25af31e93b9b34b6265f1763acb04453aa'

    headers = {
            'format': 'xml',
            'app_key': key
     }

    response = requests.request("POST", url=url, headers=headers)

    return response


def parsePhishTankResponse(xml_string):
    # create element tree object
    phish_id = 0
    in_db = False

    root = ET.fromstring(xml_string)
    results = root.find('results')
    url0 = results.find('url0')
    in_db = url0.find('in_database').text

    if in_db == 'true':
        phish_id = int(url0.find('phish_id').text)
    else:
        phish_id = -1

    return phish_id, in_db


def phishTankActivity(phish_id):
    url='https://phishtank.org/phish_detail.php?phish_id='

    id_str = str(id)

    r = requests.request("POST", url=url2, headers=headers)

    s = r.text

    if "is currently ONLINE" in s:
        print("ONLINE")
    elif ("currently offline" in s) or ("currently OFFLINE" in s):
        print("OFFLINE")
    else:
        print("INVALID")


phish_url = 'https://dappsacces-bot.co/'
url = encodePhishReqURL(phish_url)
r = queryPhishAPI(url)
phish_id, in_db = parsePhishTankResponse(r.text)

print(phish_id, in_db)
exit(1)

if in_db:
    phishTankActivity(phish_id)
