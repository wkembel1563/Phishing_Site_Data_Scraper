from parsedomains import *
import sys 

# DONE LAST TIME: writing finished.
# NEXT TIME: read and manipulate as test. 
# FIREBASE
    # TODO: set up firebase
    # TODO: integrate screenshots into firebase
# LOGGING
    # TODO: save all metadata to files to be used for later. save and retrieve in json format
    # TODO: deal with odd domains. may need other whois sources 
        # (virustotal may be good with weird domains if it has scanned them before)
    # TODO: integrate active/inactive, phishtank id's into csv write

    # TODO: deal with exceptions when certains types of data are not available
    # TODO: take into account if the csv file is empty
    # TODO: check if columns titles of write data and csv file match
    # TODO: determine if keypoint feature analysis would be a possibility 


#################
# PROGRAM LOGIC #
#################

# initialize and validate program state
args = sys.argv
data = metadata()
data.init(args)
data.print_state()

# retrieve list of domains
domains = readURLS(data)

# take screenshots of each domain
#	store in dir at PIC_PATH
screenshot_paths = screenshot(data.CURRENT_DOMAIN_ID, data.SHOT_PATH, domains)
print(screenshot_paths)
exit(1)
activity_data = checkDomainActivity(domains, screenshot_paths)

# retrieve relevant data for each domain
phishtank_data = searchPhishTank(domains)
whois_data = getWhoIs(domains)
virus_data = getVirusTotal(data.VIRUS_TOTAL_ACCESS_TOKEN, domains)
ip_data = getIpInfo(data.HANDLER, domains)

"""
Example how to access
print(virus_data[domains[0]]['data']['attributes']['last_final_url']) 
print(virus_data[domains[1]]['data']['attributes']['last_final_url']) 
print(ip_data['www.reddit.com'].country)
"""

# write data to csv file 
writeCsv(data, phishtank_data, activity_data, whois_data, virus_data, ip_data, domains)

# store metadata
# TODO: logMeta(data)
