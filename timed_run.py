#!/bin/bash
from parsedomains import *

# initialize and validate program state
args = sys.argv
data = metadata()
data.init(args)

# retrieve list of domains
print("READING URLS")
domains, awg_data = readURLS(data, remove_csv_duplicates = False)
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
