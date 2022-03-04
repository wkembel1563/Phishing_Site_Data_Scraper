import os
import base64
import socket
import csv
import whois
import csv
import ipinfo
import requests
import pandas as pd
from pandas.errors import EmptyDataError
import numpy as np
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from PIL import Image


###################
# GLOBAL VARIABLES#
###################
IPINFO_ACCESS_TOKEN = '2487a60e548477'
VIRUS_TOTAL_ACCESS_TOKEN = 'd80137e9f5e82896483095b49a7f0e73b5fd0dbc7bd98f1d418ff3ae9c83951e'
NUM_OF_ARGS = 2							# num of command line arguments
HANDLER = 0							# ipinfo handler to get ip data, updated in init()
URLFILE = 1							# arg position for name of url file
CSV_FILE_PATH = '/home/kaifeng/Desktop/empty.csv'	        # path to csv file
write_mode = 'w'						# csv file write mode upon opening
read_mode = 'r'							# csv file read mode upon opening
append_mode = 'a'                                               # csv file append mode upon opening
URL_FILE_NAME = ''						# filename containing url list, updated in init()
CURRENT_DOMAIN_ID = -1					        # last domain id used in csv file, update in init()
CSV_FILE_EXISTS = True					        # determines if the data is written to old file or new
FIELD_TITLES = []						# titles of columns in csv file, updated in init()
DIR_PATH = 'home/kaifeng/Desktop/domainShots/'                  # screenshot dir path
EMPTY = 0
#####CSV COL INDECES#######
DOMAINID = 0
PHISHID = 1
DOMAINNAME = 2
OPENCODE = 3
VSCORE = 4
VENGINES = 5
IP = 6
IPCOUNTRY = 7
REGCOUNTRY = 8
REGISTRAR = 9



####################
# HELPER FUNCTIONS #
####################
def getFieldNames():
	"""GET FIELD NAMES


	defines column titles of csv file

	
	Parameters
	----------
	( None )


	Returns  
	-------
	names : (list)
		titles of the columns in the csv file

	"""
	names = ['domain_id']
	names.append('phish_id')
	names.append('domain_name')
	names.append('open_code')
	names.append('virus_total_score')
	names.append('virus_total_engines')
	names.append('ip_address')
	names.append('ip_country')
	names.append('registrant_country')
	names.append('registrar')

	return names


def init(args): 
	""" INIT

	performs validation and initializes dynamic global data

	Parameters
	----------
	args: (list)
		list of command line arguments ['<pythonfile>' '<urlfile>']

	Returns
	-------
	( None )

	"""
	global CSV_FILE_EXISTS
	global CURRENT_DOMAIN_ID
	global HANDLER 
	global URL_FILE_NAME 
	global FIELD_NAMES

	# validate CL input length
	arg_len = len(args)
	if arg_len != NUM_OF_ARGS:
		print("Arg Error. Please follow arg format below:\npython3 <pythonfile> <urlfile>")
		exit(1)

	# initialize global variables
	HANDLER = ipinfo.getHandler(IPINFO_ACCESS_TOKEN)
	URL_FILE_NAME = args[URLFILE]
	FIELD_NAMES = getFieldNames()
	
	# collect cvs file metadata
	if os.path.exists(CSV_FILE_PATH):

		# metadata on empty file
		if os.stat(CSV_FILE_PATH).st_size == EMPTY:
			CURRENT_DOMAIN_ID = 0

		# metadata on existing file
		else: 
			df = pd.read_csv(CSV_FILE_PATH, na_values=['-', '', 'holder'])

			# determine current largest domain_id in csv record
			csv_record = df.to_numpy()
			num_records = csv_record.shape[0]
			CURRENT_DOMAIN_ID = int(df.loc[num_records - 1, FIELD_NAMES[0]])

	else:
		CSV_FILE_EXISTS = False



def readURLS():
	"""READ URLS

	reads in all urls from the list passed via command line arg.
	duplicate urls and urls conflicting with those already logged are removed.

	Parameters
	----------
	( None )

	Returns
	-------
	urls: (list)
		list of urls after conflicts/duplicates have been removed

	"""
	# Read in url's from file
	with open(URL_FILE_NAME) as f: 
		# get urls
		urls = f.readlines()

		# remove \n char
		for i, line in enumerate(urls):
			urls[i] = line[0:-1]

		# remove duplicate urls from url list
		urls = set(urls)
		urls = sorted(urls)

		# retrieve urls currently in csv record
		if CSV_FILE_EXISTS and CURRENT_DOMAIN_ID > 0:

			# retrieve current record of urls from csv file
			df = pd.read_csv(CSV_FILE_PATH, na_values=['-', '', 'holder'])
			url_rec = df.loc[:, 'domain_name'].to_numpy()

			# remove urls from list which are present in record 
			for i, url in enumerate(urls):
				if url in url_rec:
					urls.remove(urls[i])
		
	return urls



def takeScreenShots(urls):
	"""TAKE SCREENSHOTS

	uses selenium to visit and screenshot urls in input list
	screenshots are saved at dir_path and are named by their domain id

	Parameters
	----------
	urls: (list)
		list of urls to visit

	Returns
	-------
	( None )
	"""
	try:
		# set up selenium web driver
		ser = Service('/home/kaifeng/chromedriver')
		op = webdriver.ChromeOptions()
		op.add_argument('--start-maximized')
		driver = webdriver.Chrome(service=ser, options=op)

		# warn user of potential screenshot overwrite 
		message = "Screenshots will write to dir based on next csv domain id. Continue? (y/n)"
		consent = input(message) 

		# take screenshots and save to DIR_PATH
		if consent == 'y':
			domain_id = CURRENT_DOMAIN_ID + 1
			for i, url in enumerate(urls):
				# build path
				pic = '{id}.png'.format(id = domain_id + i)
				pic_path = DIR_PATH + pic

				# screenshot
				driver.get('https://' + url)
				driver.save_screenshot(pic_path)
		else:
			print("Exiting...")
			exit(1)

	except Exception as e:
	 	print('Error. Screenshot failed')
	 	exit(1)



def getWhoIs(domains): 
	"""GET WHO IS
	
	retrieve relevant whois data from python_whois api

	PYTHON WHOIS FIELDS
		_regex = {
			'domain_name':          r'Domain Name: *(.+)',
			'registrar':            r'Registrar: *(.+)',
			'whois_server':         r'Whois Server: *(.+)',
			'referral_url':         r'Referral URL: *(.+)',		# http url of whois_server
			'updated_date':         r'Updated Date: *(.+)',
			'creation_date':        r'Creation Date: *(.+)',
			'expiration_date':      r'Expir\w+ Date: *(.+)',
			'name_servers':         r'Name Server: *(.+)',		# list of name servers
			'status':               r'Status: *(.+)',			# list of statuses
			'emails':               EMAIL_REGEX,				# list of email s
			'dnssec':               r'dnssec: *([\S]+)',
			'name':                 r'Registrant Name: *(.+)',
			'org':                  r'Registrant\s*Organization: *(.+)',
			'address':              r'Registrant Street: *(.+)',
			'city':                 r'Registrant City: *(.+)',
			'state':                r'Registrant State/Province: *(.+)',
			'zipcode':              r'Registrant Postal Code: *(.+)',
			'country':              r'Registrant Country: *(.+)',
    }

	Parameters
	----------
	domains: (list)
		list of domains to gather data on

	Returns
	-------
	whois_data: (dict)
		a dictionary of the whois data for each domain
		the dictionary is indexed by domain url
	"""
	whois_data = {}

	# build dictionary of whois data for each domain
	for url in domains:
		w = whois.whois(url)
		whois_data[url] = w

	return whois_data


def getVirusTotal(domains): 
	"""GET VIRUS TOTAL 
	
	retrieves relevant data from virustotal api including:
	1) virus total phishing score for each domain
	2) virus total engines which labeled domain as a threat

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


def getIpInfo(domains): 
	"""GET IP INFO

	get info related to domain ip using ipinfo api

	IPINFO FREE PLAN FIELDS
	{
	  "ip": "66.87.125.72",
	  "hostname": "ip-66-87-125-72.spfdma.spcsdns.net",
	  "city": "Springfield",
	  "region": "Massachusetts",
	  "country": "US",
	  "loc": "42.1015,-72.5898",
	  "org": "AS10507 Sprint Personal Communications Systems",
	  "postal": "01101",
	  "timezone": "America/New_York"
	}


	Parameters
	----------
	domains: (list)
		list of domains to gather data on

	Returns
	-------
	ip_data: (dict)
		a dictionary of the ip data for each domain
		the dictionary is indexed by domain url
		
	"""
	ip_data = {}

	# get ip data for each domain
	for url in domains:
            try:
                # retrieve data
                ip = socket.gethostbyname(url)
                details = HANDLER.getDetails(ip)
                ip_data[url] = details
            except (socket.gaierror, UnicodeError):
                print("GetIpInfo Error: Invalid Domain: %s" % (url))

	return ip_data


def writeCsv(whois_data, virus_data, ip_data, domains): 
    """WRITE CSV

    creates data record in csv file for each domain

    Parameters
    ----------
    whois_data: (dict)
        whois data for each domain
        indexed by url from input url file

    virus_data: (dict)
        virus total api data for each domain
        indexed by url from input url file

    ip_data: (dict)
        ip data from ipinfo api for each domain
        indexed by url from input url file

    Returns
    -------
    ( None )
    """
    # csv file exists but is empty 
    if CURRENT_DOMAIN_ID == EMPTY: 
        FIELD_TITLES 

        # MAKE SURE FIELD TITLES MATCH DATA BEING WRITTEN!
        # write to csv 
        with open(CSV_FILE_PATH, write_mode, newline='') as csvfile: 

            # prepare write object
            writer = csv.DictWriter(csvfile, fieldnames=FIELD_TITLES)
            writer.writeheader()

            # save domain data 
            domain_id = CURRENT_DOMAIN_ID + 1
            engines_malicious = {}
            malicious_list = []
            for url in domains:
                # prepare list of engines that marked it malicious
                url_results = virus_data[url]['data']['attributes']['last_analysis_results']
                for engine in url_results.keys(): 
                    if url_results[engine]['result'] == 'malicious':
                        malicious_list.append(engine['engine_name'])
                engines_malicious[url] = malicious_list
                malicious_list = []

                # save to csv
                writer.writerow({
                    FIELD_TITLES[DOMAINID]:domain_id,
                    FIELD_TITLES[PHISHID]:'',
                    FIELD_TITLES[DOMAINNAME]:url,
                    FIELD_TITLES[OPENCODE]:'',
                    FIELD_TITLES[VSCORE]:virus_data[url]['data']['attributes']['total_votes']['malicious'],
                    FIELD_TITLES[VENGINES]:engines_malicious[url],
                    FIELD_TITLES[IP]:ip_data[url].ip,
                    FIELD_TITLES[IPCOUNTRY]:ip_data[url].country,
                    FIELD_TITLES[REGCOUNTRY]:whois_data[url].country,
                    FIELD_TITLES[REGISTRAR]:whois_data[url].registrar})
                domain_id += 1

    # append records to csv file
    elif CSV_FILE_EXISTS:
        # TODO: check if columns titles of write data and csv file match
        df = pd.read_csv("test.csv", na_values=['-', '', 'holder'])

    # csv file does not exist
    else: 
        x = 1
