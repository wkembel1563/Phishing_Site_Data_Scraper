from parsedomains import *
import sys 

#################
# PROGRAM LOGIC #
#################

# initialize and validate program state
args = sys.argv
init(args)

#####TEST
print(CURRENT_DOMAIN_ID)
exit(1)

# retrieve list of domains
domains = readURLS()

# take screenshots of each domain
#	store in dir at PIC_PATH
# takeScreenshots(domains)

# retrieve relevant data for each domain
whois_data = getWhoIs(domains)
virus_data = getVirusTotal(domains)
ip_data = getIpInfo(domains)
"""
Example how to access
print(virus_data[domains[0]]['data']['attributes']['last_final_url']) 
print(virus_data[domains[1]]['data']['attributes']['last_final_url']) 
print(ip_data['www.reddit.com'].country)
"""

# write data to csv file 
writeCsv(whois_data, virus_data, ip_data, domains)


"""
Get domain data and save as row in csv
"""
# DONE LAST TIME: removed duplicate urls, got domain id even if csv does not exist/empty
# NEXT TIME: write new domain data to csv file, integrate virustotal api
# TODO: deal with odd domains. may need other whois sources 
# 	(virustotal may be good with weird domains if it has scanned them before)
# TODO: take into account if the csv file is empty

