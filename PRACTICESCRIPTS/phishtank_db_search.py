#!/usr/bin/env python3
import requests

key = '8a2c896086a34c5a7c5a076948679e25af31e93b9b34b6265f1763acb04453aa'
database = 'online-valid.csv'

def queryPhishAPI(key, database):

    url = 'http://data.phishtank.com/data/'
    url = url + key + '/'
    url += database

    print(url)

    response = requests.request("POST", url=url)

    return response


#r = queryPhishAPI(key, database)

#print(r.text)
