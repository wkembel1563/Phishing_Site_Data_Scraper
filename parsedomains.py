import os
import csv
import json
import copy
import base64
import socket
import whois
import whois.parser
import ipinfo
import requests
import urllib.parse as up
import pandas as pd
import tensorflow as tf
import numpy as np
from ipinfo.handler_utils import cache_key
from ipwhois import IPWhois
from datetime import datetime
from pandas.errors import EmptyDataError
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from tensorflow.keras.preprocessing.image import load_img, img_to_array
from tensorflow.keras.models import load_model
from tensorflow.keras.applications.mobilenet import preprocess_input

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
    names.append('activity_img')
    names.append('activity_req')
    names.append('open_code')
    names.append('virus_total_score')
    names.append('virus_total_engines')
    names.append('ip_address')
    names.append('ip_country')
    names.append('registrant_country')
    names.append('registrar')
    names.append('time')
    names.append('awg_id')
    names.append('awg_date_discovered')

    return names




def readURLS(data, remove_csv_duplicates = True):
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
    # determine if the url file is CSV format
    CSV = False
    if '.csv' in data.URL_FILE_PATH:
        CSV = True

    if CSV:

        # extract phishtank csv data
        try:
            df = pd.read_csv(data.URL_FILE_PATH)
        except EmptyDataError:
            print("ReadURLs error. %s is empty." % (filename))
            return None
        container = {}
        awg_data = {}

        # convert records into a dictionary with APWG data
        urls = list(df.loc[:,'url'])

        for url in urls:
            found = 0
            # locate csv record for url
            for i in range(len(df)):
                record = df.loc[i]

                # store metadata in dictionary
                if record["url"] == url:
                    found = 1
                    container["awg_id"] = int(record["id"])
                    container["awg_date_discovered"] = str(record["date_discovered"])
                    awg_data[url] = copy.deepcopy(container)
                    break

            # url record not found
            if found == 0:
                print("ReadURL Error. Problem with read CSV file")
                exit(1)

            # reset for nxt iteration
            container.clear()
    else:
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
            if remove_csv_duplicates: 
                if data.CSV_FILE_EXISTS and data.CURRENT_DOMAIN_ID > 0:
                    # retrieve current record of urls from csv file
                    df = pd.read_csv(data.CSV_FILE_PATH, na_values=['-', '', 'holder'])
                    url_rec = df.loc[:, 'domain_name'].to_numpy()

                    # remove urls from list which are present in record 
                    for i, url in enumerate(urls):
                        if url in url_rec:
                            urls.remove(urls[i])

        awg_data = None

    return urls, awg_data



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
        op.set_capability('unhandledPromptBehavior', 'accept')
        op.add_argument('--start-maximized')
        op.add_argument('--disable-web-security')
        op.add_argument('--ignore-certificate-errors')

        # warn user of potential screenshot overwrite 
        #message = "Begin screenshots? (y/n): "
        #consent = input(message) 
        consent = 'y'

        # take screenshots and record activity of site
        screenshot_paths = {}
        if consent == 'y':
            driver = webdriver.Chrome(service=ser, options=op)
            # give each page 2 mins to load
            driver.set_page_load_timeout(120)
            domain_id = current_id + 1

            for i, url in enumerate(urls):
                # clean domain name
                clean_url = url.replace('https://', '')
                clean_url = clean_url.replace('http://', '')
                clean_url = clean_url.replace('www.', '')
                url_size = len(clean_url)

                # pic name starts with id of domain in csv file
                pic = '{id}'.format(id = domain_id + i)
                if url_size >= 4:
                    # name ends with first 4 chars of the url
                    pic += '_' + clean_url[0:4]
                else:
                    pic += clean_url
                pic += '.png'
                pic_path = shot_path + '/' + pic

                # screenshot
                try:
                    driver.get('https://' + clean_url)
                except Exception as e:
                    driver.save_screenshot(pic_path)
                    screenshot_paths[url] = pic_path
                    continue
                driver.save_screenshot(pic_path)

                # store pic path
                screenshot_paths[url] = pic_path

            driver.quit()
        else:
            print("Exiting...")
            exit(1)

    except Exception as e:
        print('Error. screenshot analysis failed')
        print(e)

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

        access data via:   
            activity_data[<url>]['req']     for req module data
            activity_data[<url>]['image']   for classifier data
    """
    activity_data = {}
    ACTIVE = 0
    INACTIVE = 1

    print("\nIGNORE ERROR #################")
    model = load_model('model2.h5')
    print("END IGNORE #################\n")

    print("CHECKING DOMAIN ACTIVITY...", end="")
    for url in domains:
        activity_data[url] = {}
        # get screenshot
        path = screenshot_paths[url]
        
        # prepare screenshot for analysis
        img = load_img(path, target_size=(224,224))
        img_array = img_to_array(img)
        expanded_img_array = np.expand_dims(img_array, axis=0)
        preprocessed_img = preprocess_input(expanded_img_array)

        # get cnn classifier result
        prediction = model.predict(preprocessed_img)
        if prediction[0][ACTIVE] >= 0.5:
            activity_data[url]["image"] = "active"
        else:
            activity_data[url]["image"] = "inactive"

        # get python request module result
        try:
            req_result = requests.get(url)
            if req_result.ok:
                activity_data[url]["req"] = "active"
            else:
                activity_data[url]["req"] = "inactive"
        except Exception as e:
            activity_data[url]["req"] = "unknown"

    print("DONE")

    return activity_data


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
    print("GETTING PHISHTANK DATA...", end="")

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
                container["phish_id"] = int(record["phish_id"])
                container["date"] = record["date"]
                phish_data[url] = copy.deepcopy(container)
                break

        # phishtank data not found
        if found == 0:
            container["phish_id"] = '-'
            container["date"] = '-'
            phish_data[url] = copy.deepcopy(container)

        # reset for nxt iteration
        container.clear()
    
    print("DONE")
    return phish_data


def getWhoIs(domains): 
    """GET WHO IS
    
    retrieve relevant whois data from python_whois api

    PYTHON WHOIS FIELDS
            _regex = {
                    'domain_name':
                    'registrar': 
                    'whois_server':
                    'referral_url':
                    'updated_date':
                    'creation_date':
                    'expiration_date':
                    'name_servers':  
                    'status':       
                    'emails':      
                    'dnssec':    
                    'name':     
                    'org':     
                    'address': 
                    'city':   
                    'state': 
                    'zipcode':
                    'country': }

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
    print("GETTING WHOIS DATA...", end="")

    whois_data = {}

    # build dictionary of whois data for each domain
    for url in domains:

        try:
            w = whois.whois(url)
            keys = list(w.keys())

            # convert datetime objects to strings
            #   updated date
            time_pattern = "%m/%d/%Y, %H:%M:%S"
            upd_date = 'updated_date'
            c_date = 'creation_date'
            exper_date = 'expiration_date'
            if upd_date in keys:
                if isinstance(w[upd_date], list):
                    for i in range(len(w[upd_date])): 
                        up_date = w[upd_date][i].strftime(time_pattern)
                        w[upd_date][i] = up_date
                elif w[upd_date] is not None:
                    up_date = w[upd_date].strftime(time_pattern)
                    w[upd_date] = up_date

            #   creation date
            if c_date in keys:
                if isinstance(w[c_date], list):
                    for i in range(len(w[c_date])): 
                        create_date = w[c_date][i].strftime(time_pattern)
                        w[c_date][i] = create_date
                elif w[c_date] is not None:
                    create_date = w[c_date].strftime(time_pattern)
                    w[c_date] = create_date

            #   expiration date
            if exper_date in keys:
                if isinstance(w[exper_date], list):
                    for i in range(len(w[exper_date])): 
                        exp_date = w[exper_date][i].strftime(time_pattern)
                        w[exper_date][i] = exp_date
                elif w[exper_date] is not None:
                    exp_date = w[exper_date].strftime(time_pattern)
                    w[exper_date] = exp_date

        except whois.parser.PywhoisError:
            w = {}

        whois_data[url] = w

    print("DONE")
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
    print("GETTING VIRUSTOTAL DATA...", end="")
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

    print("DONE")
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
    print("GETTING IP DATA...", end="")
    ip_data = {}

    # get ip data for each domain
    for url in domains:
        try:
            # retrieve data
            parsed_url = up.urlparse(url)
            ip = socket.gethostbyname(parsed_url.netloc)
            details = handler.getDetails(ip)
            ip_data[url] = details
        except (socket.gaierror, UnicodeError):
            ip_data[url] = failedFetch()

    print("Done")
    return ip_data

def logMeta(data, 
            phishtank_data,
            activity_data,
            whois_data,
            virus_data,
            ip_data, 
            awg_data,
            domains): 
    """LOG METADATA

    stores all metadata created for each url in a file

    data is stored as a dictionary which can be indexed using the url
    and the type of data

    i.e. to get phishtank data out of the file
        log[url]["phishtank_data"]

    Parameters
    ----------
    data: (metadata class object)
        contains metadata about program state and files

    phishtank_data: (dict)
        contains url phishtank id and date added

    activity_data: (dict)
        contains cnn classifier activity prediction and request
        module result for each url

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
    print("LOGGING METADATA...", end="")
    log = {}
    domain_id = data.CURRENT_DOMAIN_ID + 1

    for i, url in enumerate(domains):
        # clean domain name
        clean_url = url.replace('https://', '')
        clean_url = clean_url.replace('http://', '')
        clean_url = clean_url.replace('www.', '')
        url_size = len(clean_url)

        # pic name starts with id of domain in csv file
        file_name = '{id}'.format(id = domain_id + i)
        if url_size >= 4:
            # name ends with first 4 chars of the url
            file_name += '_' + clean_url[0:4]
        else:
            file_name += clean_url
        file_name += '.json'
        file_path = data.META_PATH + '/' + file_name

        with open(file_path, 'w') as logfile:
            log["url"] = url
            log["phishtank_data"] = phishtank_data[url]
            log["activity_data"] = activity_data[url]
            log["whois_data"] = whois_data[url]
            log["virus_data"] = virus_data[url]

            if awg_data is not None:
                log["awg_data"] = awg_data[url]

            # convert ip Details object to dict
            if ip_data[url].ip is not '-':
                ip_key = cache_key(ip_data[url].ip)
                ip_dict = data.HANDLER.cache[ip_key]
                log["ip_data"] = ip_dict

            log_js = json.dumps(log, indent=1, sort_keys=True)
            logfile.write(log_js)

            # reset
            log.clear()

    print("DONE")


def writeCsv(data, 
            phishtank_data,
            activity_data,
            whois_data,
            virus_data,
            ip_data, 
            awg_data,
            domains): 
    """WRITE CSV

    creates data record in csv file for each domain

    Parameters
    ----------
    data: (metadata class object)
        contains metadata about program state and files

    phishtank_data: (dict)
        contians url phishtank id and date added

    activity_data: (dict)
        contains cnn classifier activity prediction and request
        module result for each url

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
    print("WRITING TO CSV...", end="")

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
            try:
                url_results = virus_data[url]['data']['attributes']['last_analysis_results']
                for engine in url_results.keys(): 
                    if url_results[engine]['result'] in blacklist:
                        malicious_list.append(url_results[engine]['engine_name'])
                engines_malicious[url] = malicious_list
                
                try:
                    m_score = virus_data[url]['data']['attributes']['last_analysis_stats']['malicious']
                except Exception as e:
                    m_score = 0

                try:
                    s_score = virus_data[url]['data']['attributes']['last_analysis_stats']['suspicious']
                except Exception as e:
                    s_score = 0

                v_score = m_score + s_score
            except Exception as e:
                print("No virus total record")
                v_score = 0
                engines_malicious[url] = "No data"
            
            # reset list
            malicious_list = []

            # save to csv
            #   stopgaps
            if whois_data[url] == {}:
                country = ''
                registrar = ''
            else:
                country = whois_data[url].country
                registrar = whois_data[url].registrar
            if awg_data is None:
                awg_id = '-'
                awg_date = '-'
            else:
                awg_id = awg_data[url]["awg_id"]
                awg_date = awg_data[url]["awg_date_discovered"]

            if ip_data[url].ip is not '-':
                ip_country = ip_data[url].details.get('country', None)

            writer.writerow({
                data.FIELD_TITLES[data.DOMAINID]:domain_id,
                data.FIELD_TITLES[data.PHISHID]:phishtank_data[url]["phish_id"],
                data.FIELD_TITLES[data.DOMAINNAME]:url,
                data.FIELD_TITLES[data.ACTIVITY_IMG]:activity_data[url]["image"],
                data.FIELD_TITLES[data.ACTIVITY_REQ]:activity_data[url]["req"],
                data.FIELD_TITLES[data.OPENCODE]:'-',
                data.FIELD_TITLES[data.VSCORE]:v_score,
                data.FIELD_TITLES[data.VENGINES]:engines_malicious[url],
                data.FIELD_TITLES[data.IP]:ip_data[url].ip,
                data.FIELD_TITLES[data.IPCOUNTRY]:ip_country,
                data.FIELD_TITLES[data.REGCOUNTRY]:country,
                data.FIELD_TITLES[data.REGISTRAR]:registrar,
                data.FIELD_TITLES[data.TIME]:data.now,
                data.FIELD_TITLES[data.AWG_ID]:awg_id,
                data.FIELD_TITLES[data.AWG_DATE]:awg_date})
            domain_id += 1

        # update current domain id
        data.CURRENT_DOMAIN_ID = domain_id - 1

    print("DONE")


###########################
# OBJECTS GLOBAL VARIABLES#
###########################
class metadata:

    def __init__(self):
        # ACCESS TOKENS
        self.IPINFO_ACCESS_TOKEN = '2487a60e548477'                          
        self.VIRUS_TOTAL_ACCESS_TOKEN = 'd80137e9f5e82896483095b49a7f0e73b5fd0dbc7bd98f1d418ff3ae9c83951e'
        self.twilio_sid = 'AC643cb218d386523498c4e54cab0fdcf4' 
        self.twilio_auth_token = '4794ef24fc522c0f5569afbd672896f0' 

        # FILES PATHS
        self.CSV_FILE_CHOICE = 'phish_data.csv'           # csv file to write to 
        self.URL_FILE_CHOICE = 'phishtank_urls.txt'      # url file to read from
        self.META_FILE_CHOICE = 'log.txt'
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
        self.URLFILE = 1                                # arg position for name of url file
        self.write_mode = 'w'                            # csv file write mode upon opening
        self.read_mode = 'r'                             # csv file read mode upon opening
        self.append_mode = 'a'                           # csv file append mode upon opening
        self.now = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")

        ###################
        # CSV COL INDECES #
        ###################
        self.DOMAINID = 0
        self.PHISHID = 1
        self.DOMAINNAME = 2
        self.ACTIVITY_IMG = 3
        self.ACTIVITY_REQ = 4
        self.OPENCODE = 5
        self.VSCORE = 6
        self.VENGINES = 7
        self.IP = 8
        self.IPCOUNTRY = 9
        self.REGCOUNTRY = 10
        self.REGISTRAR = 11
        self.TIME = 12
        self.AWG_ID = 13
        self.AWG_DATE = 14

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
        self.CSV_FILE_PATH = base_path + self.CSV_RELATIVE_PATH + '/' + self.CSV_FILE_CHOICE
        self.SHOT_PATH = base_path + self.SHOT_RELATIVE_PATH
        #self.META_PATH = base_path + self.META_RELATIVE_PATH + '/' + self.META_FILE_CHOICE
        self.META_PATH = base_path + self.META_RELATIVE_PATH

        # validate CL input length
        #   two args means a url file was passed, contains relative path
        arg_len = len(args)
        if arg_len == 2:
            self.URL_FILE_PATH = base_path + '/' + args[self.URLFILE]

        #   invalid num of args
        elif arg_len != self.NUM_OF_ARGS:
                print("Arg Error. Invalid CL input format")
                exit(1)

        #   one arg means use default files
        else:
            print("\nNO URL FILE SPECIFIED. Reverting to default...\n")
            self.URL_FILE_PATH = base_path + self.URL_RELATIVE_PATH + '/' + self.URL_FILE_CHOICE

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
