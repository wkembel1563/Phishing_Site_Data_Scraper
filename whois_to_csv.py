from parsedomains import *
import sys 

# DONE LAST TIME: writing finished.
# NEXT TIME: read and manipulate as test. 
# FIREBASE
    # TODO: set up firebase
    # TODO: integrate screenshots into firebase
# LOGGING
    # create backup file each time the logs are changed
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
screenshot_paths = screenshot(data.CURRENT_DOMAIN_ID, data.SHOT_PATH, domains)

# determine if the domains are active
activity_data = checkDomainActivity(domains, screenshot_paths)

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
        domains)

# write data to csv file 
writeCsv(data, 
        phishtank_data,
        activity_data,
        whois_data,
        virus_data,
        ip_data, 
        domains)

