#!/bin/bash
from parsedomains import *

# initialize and validate program state
args = sys.argv
data = metadata()
data.init(args)

# update url list
MAX_URL_NUM = 1000
if "phish_urls" in data.URL_FILE_PATH:
        source_url_dir = os.path.join(data.BASE_PATH, '../splab_phish_urls/output/')
        collected_phish_url_file = os.path.join(data.BASE_PATH, 'URLFILES/phish_urls.csv')

        print("UPDATING PHISHTANK URLS")
        updateUrls(phish_url_dir, collected_phish_url_file, max_num_urls=MAX_URL_NUM)

elif "cert_urls" in data.URL_FILE_PATH:
        source_url_dir = os.path.join(data.BASE_PATH, '../splab_phish_urls/output_2/')
        collected_cert_url_file = os.path.join(data.BASE_PATH, 'URLFILES/cert_urls.csv')

        print("UPDATING CERTSTREAM URLS")
        updateUrls(cert_url_dir, collected_cert_url_file, max_num_urls=MAX_URL_NUM)

print("DONE UPDATING URLS")


# retrieve list of domains
print("READING URLS")
domains, awg_data = readUrls(data, remove_csv_duplicates = False)
print("DONE READING URLS")

# prep messaging functionality
#client = Client(data.twilio_sid, data.twilio_auth_token) 

############### MODEL
model_name = "model2.h5"
#####################

# prepare domain activity classifier
print("\nIGNORE ERROR #################")
model_path = os.path.join(data.BASE_PATH, model_name)
model = load_model(model_path)
print("END IGNORE #################\n")

# reset for next run
print("\n____RUN____")
data.now = int(time())
print("\nTime: %s\n" % (datetime.now().strftime("%m/%d/%Y, %H:%M:%S")))
data.print_state()

# take screenshots of each domain
print("TAKING SCREENSHOTS")
screenshot_paths = screenshot(data.CURRENT_DOMAIN_ID, data.SHOT_PATH, domains)
print("DONE TAKING SCREENSHOTS")

# determine if the domains are active
activity_data = checkDomainActivity(domains, screenshot_paths, model)

# retrieve relevant data for each domain
whois_data = getWhoIs(domains)
phishtank_data = searchPhishTank(domains)
virus_data = getVirusTotal(data.VIRUS_TOTAL_ACCESS_TOKEN, domains)
ip_data = getIpInfo(data.HANDLER, domains)

# store metadata
logMeta(data, 
        phishtank_data,
        activity_data,
        whois_data,
        virus_data,
        ip_data, 
        awg_data,
        domains)

# write data to csv file 
writeCsv(data, 
        phishtank_data,
        activity_data,
        whois_data,
        virus_data,
        ip_data, 
        awg_data,
        domains)

print("__Done__\n\n")
