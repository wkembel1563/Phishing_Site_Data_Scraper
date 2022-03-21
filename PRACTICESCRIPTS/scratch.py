import requests
import base64
import pandas as pd
import json

VIRUS_TOTAL_ACCESS_TOKEN = "d80137e9f5e82896483095b49a7f0e73b5fd0dbc7bd98f1d418ff3ae9c83951e"

def getVirusTotal(domains): 
	"""GET VIRUS TOTAL 
	
	retrieves relevant data from virustotal api including:
	1) virus total phishing score for each domain
	2) virus total engines which labeled domain as a threat

	
	EXAMPLE SCAN REQUEST RESPONSE
	{
	  "data": {
		"type": "analysis",
		"id": "u-dd014af5ed6b38d9130e3f466f850e46d21b951199d53a-1646387247"
	  }
	}

	Parameters
	----------
	domains: (list)
		list of domains to gather data on

	Returns
	-------
	virus_data: (dict)
		a dictionary of the virustotal data for each domain
		the dictionary is indexed by domain url
	"""
	global VIRUS_TOTAL_ACCESS_TOKEN 
	virus_data = {}

	# request virustotal scan each domain in list
	for domain in domains:
            # encode domain
            payload = "url=" + domain
            domain_id = base64.urlsafe_b64encode(domain.encode()).decode().strip("=")

            # get scan report 
            url = "https://www.virustotal.com/api/v3/urls"
            url = url + '/' + domain_id
            headers = {

                "Accept": "application/json",

                "x-apikey": VIRUS_TOTAL_ACCESS_TOKEN

            }
            response = requests.request("GET", url, headers=headers)
            report = response.json()

            # create dict entry for report
            virus_data[domain] = report

	return virus_data


########
# MAIN #
########

domains = ['wwww.google.com', 'www.reddit.com']
virus_data = getVirusTotal(domains)
#print(virus_data[domains[0]]) 
print(virus_data[domains[0]]['data']['attributes']['last_final_url']) 
print(virus_data[domains[1]]['data']['attributes']['last_final_url']) 
# print(virus_data[domains[0]]['last_analysis_stats']['harmless'])
# print('\n')
# print(virus_data[domains[1]]['last_analysis_stats']['harmless'])

#########
exit(1)
#########






""" TEST
# VIRUS TOTAL SCAN REQUEST 

# request headers
# url = "https://www.virustotal.com/api/v3/urls"
# 
# domain = "www.google.com"
# payload = "url=" + domain
# 
# headers = {
# 
#     "Accept": "application/json",
# 
#     "x-apikey": "d80137e9f5e82896483095b49a7f0e73b5fd0dbc7bd98f1d418ff3ae9c83951e",
# 
#     "Content-Type": "application/x-www-form-urlencoded"
# 
# }
# 
# response = requests.request("POST", url, data=payload, headers=headers)
#json_data = response.json()
#scan_id = json_data['data']['id']




# TODO Test data collection. Switch to append
# TODO read last id from file, then append new domain_id
with open(CSV_FILE_PATH, write_mode, newline='') as csvfile: 

	# define csv file columns
	fieldnames = getFieldNames()

	# prepare csv write object
	writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

	# retrieve domain data and save to file
	writeCsv(writer, urls, csvfile)
"""

"""
import re
import json
from urllib.request import urlopen
TO PARSE JSON DATA with json library
	response = urlopen(url)
	data = json.load(response)
	print("Library Data:")
	print(data['ip'])
	print(data['org'])
	print(data['city'])
	print(data['country'])
"""
