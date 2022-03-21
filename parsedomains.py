import os
import copy
import base64
import socket
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



def screenshot(current_id, shot_path, urls):
    """SCREENSHOT ANALYSIS

    uses selenium to visit and screenshot urls in input list
    screenshots are saved at dir_path and are named by their domain id

    Parameters
    ----------
    current_id:

    shot_path:

    urls: (list)
        list of urls to visit

    Returns
    -------
    screenshot_paths: (dictionary)
        full path to each screenshot, uses url as key
    """
    try:
        # set up selenium web driver
        ser = Service('/home/kaifeng/chromedriver')
        op = webdriver.ChromeOptions()
        op.add_argument('--start-maximized')

        # warn user of potential screenshot overwrite 
        message = "Screenshots will save to dir based on next domain id. Continue? (y/n)"
        consent = input(message) 

        # take screenshots and record activity of site
        screenshot_paths = {}
        if consent == 'y':
            driver = webdriver.Chrome(service=ser, options=op)
            domain_id = current_id + 1
            for i, url in enumerate(urls):
                # build path
                url = url.replace('https://', '')
                pic = '{id}.png'.format(id = domain_id + i)
                pic_path = shot_path + pic

                # screenshot
                driver.get('https://' + url)
                driver.save_screenshot(pic_path)

                # save activity status
                screenshot_paths[url] = pic_path
        else:
            print("Exiting...")
            exit(1)

    except Exception as e:
        print('Error. screenshot analysis failed')
        print(e)
        exit(1)

    return screenshot_paths


def checkDomainActivity(domains, screenshot_paths):
    """CHECK DOMAIN ACTIVITY

    uses request module and CNN image classifier to determine
    if a domain is currently active or inactive

    Parameters
    ----------
    domains: (list)
        urls to check 

    screenshot_paths: (dictionary)
        paths to screenshot of each url
        url is the key to its own path

    Returns
    -------
    activity_data: (dict)
        activity data as classified by CNN model and python requests
        module for each url

        access data via:   activity_data[<url>]['req' or 'image']
    """
    x = 1

def searchPhishTank(domains):
    """SEARCH PHISH TANK

    retrieve url, date added, phishtank id for each url using the phisherman scraper

    Parameters:
    -----------
    domains: (list)
        urls to lookup

    Returns:
    --------
    phish_data: (dictionary)
        phishtank data for url including data added to phishtank and phishtank id
        data can be accessed via 'phish_data[<url>]['date' or 'phish_id']
    """
    # generate path to file
    path_to_file = os.getcwd()
    filename = 'log.csv'
    full_path = path_to_file + '/PHISHERMAN/' + filename

    # extract phishtank csv data
    try:
        df = pd.read_csv(full_path)
    except EmptyDataError:
        print("Search phishtank error. %s is empty." % (filename))
        return None

    # encapsulate url with its phishtank data
    phish_data = {}
    container = {}

    for url in domains:
        found = 0
        # search each phishtank log record
        for i in range(len(df)):
            record = df.loc[i]

            # phishtank data found
            if record["url"] == url:
                found = 1
                container["phish_id"] = record["phish_id"]
                container["date"] = record["date"]
                phish_data[url] = copy.deepcopy(container)
                break

        # phishtank data not found
        if found == 0:
            print('t')
            container["phish_id"] = '-'
            container["date"] = '-'
            phish_data[url] = copy.deepcopy(container)

        # reset for nxt iteration
        container.clear()
    
    return phish_data


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
        # ACCESS TOKENS
        self.IPINFO_ACCESS_TOKEN = '2487a60e548477'                          
        self.VIRUS_TOTAL_ACCESS_TOKEN = 'd80137e9f5e82896483095b49a7f0e73b5fd0dbc7bd98f1d418ff3ae9c83951e'

        # FILES PATHS
        self.CSV_FILE_CHOICE = 'phish_log.csv'           # csv file to write to 
        self.URL_FILE_CHOICE = 'phishtank_urls.txt'      # url file to read from
        self.CSV_RELATIVE_PATH = '/CSV'                  # relative path to csv folder 
        self.SHOT_RELATIVE_PATH = '/SCREENSHOTS'         # relative path to screenshot folder 
        self.URL_RELATIVE_PATH = '/URLFILES'             # relative path to url dir
        self.META_RELATIVE_PATH = '/META'                # relative path to metadata dir

                                                         # PATHS BELOW ARE UPDATED IN init()
        self.CSV_FILE_PATH = ''	                         # absolute path to csv file
        self.SHOT_PATH = ''                              # absolute path to screenshot dir
        self.META_PATH = ''                              # absolute path to metadata dir
        self.URL_FILE_PATH = ''                          # absolute path to urlfile 

        # VALUES UPDATED IN init()
        self.HANDLER = 0                                 # ipinfo handler to get ip data
        self.CSV_FILE_EXISTS = True                      # determines if the data is written to old file or new
        self.FIELD_TITLES = []                           # titles of columns in csv file
        self.CURRENT_DOMAIN_ID = -1                      # last domain id used in csv file
        self.EMPTY = 0                                   # used to determine if csv file is empty

        # CONSTS
        self.NUM_OF_ARGS = 1                             # num of command line arguments
        #self.URLFILE = 1                                # arg position for name of url file
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

    def print_state(self):
        # File paths
        print("CSV file path:")
        print(self.CSV_FILE_PATH)
        print("\nURL file path:")
        print(self.URL_FILE_PATH)
        print("\nMETADATA file path:")
        print(self.META_PATH)
        print("\nSCREENSHOT file path:")
        print(self.SHOT_PATH)

        # Domain id
        print("\nCurrent domain id: %d" % (self.CURRENT_DOMAIN_ID))

    def init(self, args): 
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
