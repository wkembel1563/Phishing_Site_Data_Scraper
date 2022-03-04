import json
import requests

# TODO: catch errors before writing to csv


scanurl = 'https://www.virustotal.com/vtapi/v2/url/scan'
reporturl = 'https://www.virustotal.com/vtapi/v2/url/report'
url = 'https://www.thenehemiahcompany.com'

params = {
	'apikey': 'd80137e9f5e82896483095b49a7f0e73b5fd0dbc7bd98f1d418ff3ae9c83951e', 
	'url':url
}


# POST SCAN REQUEST
response = requests.post(scanurl, data=params)
json_data = response.json()
scan_id = json_data["scan_id"]
string_data = json.dumps(json_data, indent=4)
print("POST RESPONSE") 
print(string_data)

# GET REQUEST
params = {
	'apikey': 'd80137e9f5e82896483095b49a7f0e73b5fd0dbc7bd98f1d418ff3ae9c83951e', 
	'resource':scan_id
}
response = requests.post(reporturl, data=params)
json_data = response.json()
string_data = json.dumps(json_data, indent=4)
print("REPORT") 
print(string_data)



#response_string = json.loads(response)

#print(response_string)

# data = {
# 	"person":{
# 		"name": "Will",
# 		"age": 27
# 	}
# }
# 
# with open("test.json", "w") as testfile:
# 	json.dump(data, testfile, indent=4); 
# 
# string = json.dumps(data, indent=4)
# 
# print(string)
# 
# 
# decode = json.loads(string)
# 
# print(decode["person"]["name"]) 
