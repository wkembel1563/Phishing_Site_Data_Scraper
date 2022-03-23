from parsedomains import *
import sys 
import time
from twilio.rest import Client

# initialize and validate program state
args = sys.argv
data = metadata()
data.init(args)

# retrieve list of domains
domains, awg_data = readURLS(data, remove_csv_duplicates = False)

# 4 hrs (14,400s) / 10 mins (600s)
ROUND_LIMIT = 100000
for i in range(ROUND_LIMIT):
    # reset
    print("\n____RUN %d____" % (i))
    data.now = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
    data.print_state()

    # mark start time
    t1 = datetime.now()

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

    print("__Done__")

    # mark end time
    t2 = datetime.now()
    time_spent = (t2 - t1).seconds

    # send me message the run as ended

    # wait 10 minutes before next run
    while time_spent < 600:
        time.sleep(10)
        t2 = datetime.now()
        time_spent = (t2 - t1).seconds
