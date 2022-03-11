import os
import base64
import socket
import whois
import csv
import ipinfo
import requests
import pandas as pd
# from pandas.errors import EmptyDataError
import numpy as np
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from PIL import Image

# TODO: test system after adjusting all paths
    # path to urls
        # only reading
    # path to screenshots
        # only writing right now, but may want to add reading to avoid overwrite
    # path to csv
        # reading and writing
    # path to metadata
# TODO: deal with exceptions when certains types of data are not available
# TODO: get all data inputting to csv correctly. Should just have to change a few lines to add more data
            # TODO: CHANGE this to be more modular. increasing dimensionality of data should add col automatically
            # pandas may be good for this
# TODO: save all metadata to files to be used for later. save and retrieve in json format
        # write to META dir
# TODO: get phishtank api key
# TODO: automatically detect if a domain is availabe via screenshot or html (screenshot preferred)
# TODO: set up firebase
# TODO: determine if keypoint feature analysis would be a possibility 


####################
# HELPER FUNCTIONS #
####################
class failedFetch:
    def __init__(self):
        self.ip = "-"
        self.country = "-"


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




def readURLS(data):
    """READ URLS

    reads in all urls from the list passed via command line arg.
    duplicate urls and urls conflicting with those already logged are removed.

    Parameters
    ----------
    data: (metadata class object)
        contains metadata about program state needed to 
        open files properly

    Returns
    -------
    urls: (list)
            list of urls after conflicts/duplicates have been removed

    """

    # Read in url's from file
    with open(data.URL_FILE_PATH) as f: 
        # get urls
        urls = f.readlines()

        # remove \n char
        for i, line in enumerate(urls):
            urls[i] = line[0:-1]

        # remove duplicate urls from url list
        urls = set(urls)
        urls = sorted(urls)

        # retrieve urls currently in csv record
        # filter out duplicates from list
        if data.CSV_FILE_EXISTS and data.CURRENT_DOMAIN_ID > 0:

            # retrieve current record of urls from csv file
            df = pd.read_csv(data.CSV_FILE_PATH, na_values=['-', '', 'holder'])
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

		# take screenshots and save to SHOT_PATH
		if consent == 'y':
			domain_id = CURRENT_DOMAIN_ID + 1
			for i, url in enumerate(urls):
				# build path
				pic = '{id}.png'.format(id = domain_id + i)
				pic_path = SHOT_PATH + pic

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


def getVirusTotal(token, domains): 
	"""GET VIRUS TOTAL 
	
	retrieves relevant data from virustotal api including:
	1) virus total phishing score for each domain
	2) virus total engines which labeled domain as a threat

	Parameters
	----------
        token: (string)
            virus total access token 

	domains: (list)
		list of domains to gather data on

	Returns
	-------
	virus_data: (dict)
		a dictionary of the virustotal data for each domain
		the dictionary is indexed by domain url
	"""
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

                "x-apikey": token

            }
            response = requests.request("GET", url, headers=headers)
            report = response.json()

            # create dict entry for report
            virus_data[domain] = report

	return virus_data


def getIpInfo(handler, domains): 
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
    handler: (ipinfo handler class object)
        handler object used to retrieve ip details

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
            details = handler.getDetails(ip)
            ip_data[url] = details
        except (socket.gaierror, UnicodeError):
            print("GetIpInfo Error: Invalid Domain: %s" % (url))
            ip_data[url] = failedFetch()

    return ip_data


def writeCsv(data, whois_data, virus_data, ip_data, domains): 
    """WRITE CSV

    creates data record in csv file for each domain

    Parameters
    ----------
    data: (metadata class object)
        contains metadata about program state and files

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
    # set csv write mode based on state of file
    if data.CURRENT_DOMAIN_ID == data.EMPTY: 
        data.write_mode = 'w' 

    # append records to csv file
    elif data.CSV_FILE_EXISTS:
        data.write_mode = 'a'

    # csv file does not exist
    else: 
        print("Write CSV Error. CSV file does not exist")
        exit(1)

    # write to csv 
    with open(data.CSV_FILE_PATH, data.write_mode, newline='') as csvfile: 

        # prepare write object
        writer = csv.DictWriter(csvfile, fieldnames=data.FIELD_TITLES)
        if data.write_mode == 'w':
            writer.writeheader()

        # save domain data 
        domain_id = data.CURRENT_DOMAIN_ID + 1
        engines_malicious = {}
        malicious_list = []
        blacklist = ['malicious', 'phishing', 'suspicious', 'malware']
        for url in domains:
            # prepare list of engines that concluded malicious
            url_results = virus_data[url]['data']['attributes']['last_analysis_results']
            for engine in url_results.keys(): 
                if url_results[engine]['result'] in blacklist:
                    malicious_list.append(url_results[engine]['engine_name'])
            engines_malicious[url] = malicious_list

            m_score = virus_data[url]['data']['attributes']['last_analysis_stats']['malicious']
            s_score = virus_data[url]['data']['attributes']['last_analysis_stats']['suspicious']
            v_score = m_score + s_score
            
            # reset list
            malicious_list = []

            # save to csv
            writer.writerow({
                data.FIELD_TITLES[data.DOMAINID]:domain_id,
                data.FIELD_TITLES[data.PHISHID]:'',
                data.FIELD_TITLES[data.DOMAINNAME]:url,
                data.FIELD_TITLES[data.OPENCODE]:'',
                data.FIELD_TITLES[data.VSCORE]:v_score,
                data.FIELD_TITLES[data.VENGINES]:engines_malicious[url],
                data.FIELD_TITLES[data.IP]:ip_data[url].ip,
                data.FIELD_TITLES[data.IPCOUNTRY]:ip_data[url].country,
                data.FIELD_TITLES[data.REGCOUNTRY]:whois_data[url].country,
                data.FIELD_TITLES[data.REGISTRAR]:whois_data[url].registrar})
            domain_id += 1




###################
# GLOBAL VARIABLES#
###################
class metadata:

    def __init__(self):
        self.IPINFO_ACCESS_TOKEN = '2487a60e548477'                          
        self.VIRUS_TOTAL_ACCESS_TOKEN = 'd80137e9f5e82896483095b49a7f0e73b5fd0dbc7bd98f1d418ff3ae9c83951e'
        self.CSV_FILE_CHOICE = 'empty.csv'               # csv file to write to (empty test file)
        #self.CSV_FILE_CHOICE = 'Phishing.csv'               # csv file to write to (full record)
        self.URL_FILE_CHOICE = 'urls.txt'                # url file to write to
        self.CSV_RELATIVE_PATH = '/CSV'                  # relative path to csv folder 
        self.SHOT_RELATIVE_PATH = '/SCREENSHOTS'         # relative path to screenshot folder 
        self.URL_RELATIVE_PATH = '/URLFILES'             # relative path to url dir
        self.META_RELATIVE_PATH = '/META'
        self.CSV_FILE_PATH = ''	                         # absolute path to csv file, updated in init()
        self.SHOT_PATH = ''                              # absolute path to screenshot dir, updated in init()
        self.META_PATH = ''                              # absolute path to metadata dir, updated in init()
        self.URL_FILE_PATH = ''                          # absolute path to urlfile 
        self.NUM_OF_ARGS = 1                             # num of command line arguments
        self.HANDLER = 0                                 # ipinfo handler to get ip data, updated in init()
        #self.URLFILE = 1                                # arg position for name of url file
        self.CURRENT_DOMAIN_ID = -1                      # last domain id used in csv file, update in init()
        self.CSV_FILE_EXISTS = True                      # determines if the data is written to old file or new
        self.FIELD_TITLES = []                           # titles of columns in csv file, updated in init()
        self.EMPTY = 0                                   # used to determine if csv file is empty
        self.write_mode = 'w'                            # csv file write mode upon opening
        self.read_mode = 'r'                             # csv file read mode upon opening
        self.append_mode = 'a'                           # csv file append mode upon opening

        ###################
        # CSV COL INDECES #
        ###################
        self.DOMAINID = 0
        self.PHISHID = 1
        self.DOMAINNAME = 2
        self.OPENCODE = 3
        self.VSCORE = 4
        self.VENGINES = 5
        self.IP = 6
        self.IPCOUNTRY = 7
        self.REGCOUNTRY = 8
        self.REGISTRAR = 9


    def validate(self, args): 
        """ INIT

        performs validation on CL input and initializes 
        dynamic global data

        Parameters
        ----------
        args: (list)
                list of command line arguments ['<pythonfile>' '<urlfile>']

        Returns
        -------
        ( None )

        """

        # build file paths
        # to urlfile dir, screenshot dir, metadata dir and csv file
        base_path = os.getcwd()
        self.URL_FILE_PATH = base_path + self.URL_RELATIVE_PATH + '/' + self.URL_FILE_CHOICE
        self.CSV_FILE_PATH = base_path + self.CSV_RELATIVE_PATH + '/' + self.CSV_FILE_CHOICE
        self.SHOT_PATH = base_path + self.SHOT_RELATIVE_PATH
        self.META_PATH = base_path + self.META_RELATIVE_PATH

        # validate CL input length
        arg_len = len(args)
        if arg_len != self.NUM_OF_ARGS:
                #print("Arg Error. Please follow arg format below:\npython3 <pythonfile> <urlfile>")
                print("Arg Error. Please follow arg format below:\npython3 <pythonfile>")
                exit(1)

        # initialize global variables
        self.HANDLER = ipinfo.getHandler(self.IPINFO_ACCESS_TOKEN)
        self.FIELD_TITLES = getFieldNames()
        
        # establish domain id of next domain to be logged
        if os.path.exists(self.CSV_FILE_PATH):

            # empty files start with domain id 0
            if os.stat(self.CSV_FILE_PATH).st_size == self.EMPTY or os.stat(self.CSV_FILE_PATH).st_size == 1:
                self.CURRENT_DOMAIN_ID = 0

            # existing files start with last domain id stored
            else: 
                df = pd.read_csv(self.CSV_FILE_PATH, na_values=['-', '', 'holder'])

                # determine current largest domain_id in csv record
                csv_record = df.to_numpy()
                num_records = csv_record.shape[0]
                self.CURRENT_DOMAIN_ID = int(df.loc[num_records - 1, self.FIELD_TITLES[0]])

        # csv file has not been created yet
        else:
            self.CSV_FILE_EXISTS = False
