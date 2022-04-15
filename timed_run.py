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
        collected_url_file = os.path.join(data.BASE_PATH, 'URLFILES/phish_urls.csv')
        print("UPDATING PHISHTANK URLS...")

elif "cert_urls" in data.URL_FILE_PATH:
        source_url_dir = os.path.join(data.BASE_PATH, '../splab_phish_urls/output_2/')
        collected_url_file = os.path.join(data.BASE_PATH, 'URLFILES/cert_urls.csv')
        print("UPDATING CERTSTREAM URLS...")
updateUrls(source_url_dir, collected_url_file, max_num_urls=MAX_URL_NUM)
print("DONE\n")


# retrieve list of domains
print("READING URLS...")
domains, awg_data = readUrls(data, remove_csv_duplicates = False)
print("DONE\n")

# prep messaging functionality
#client = Client(data.twilio_sid, data.twilio_auth_token) 


# prepare domain activity classifier
############### MODEL
model_name = "model2.h5"
#####################
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
print("TAKING SCREENSHOTS...")
screenshot_paths = screenshot(data.CURRENT_DOMAIN_ID, data.SHOT_PATH, domains)
print("DONE\n")

# determine if the domains are active
print("CHECKING DOMAIN ACTIVITY...")
activity_data = checkDomainActivity(domains, screenshot_paths, model)
print("DONE\n")

# retrieve relevant data for each domain
print("GETTING WHOIS DATA...")
whois_data = getWhoIs(domains)
print("DONE\n")

print("GETTING PHISHTANK DATA...")
phishtank_data = searchPhishTank(domains)
print("DONE\n")

print("GETTING VIRUSTOTAL DATA...")
virus_data = getVirusTotal(data.VIRUS_TOTAL_ACCESS_TOKEN, domains)
print("DONE\n")

print("GETTING IP DATA...")
ip_data = getIpInfo(data.HANDLER, domains)
print("DONE\n")

# store metadata
print("LOGGING METADATA...")
logMeta(data, 
        phishtank_data,
        activity_data,
        whois_data,
        virus_data,
        ip_data, 
        awg_data,
        domains)
print("DONE\n")

# write data to csv file
print("WRITING DATA...")
writeCsv(data, 
        phishtank_data,
        activity_data,
        whois_data,
        virus_data,
        ip_data, 
        awg_data,
        domains)
print("DONE\n")

print("__Run Complete__\n\n")
