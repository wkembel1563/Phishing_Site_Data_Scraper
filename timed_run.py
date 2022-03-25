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

# prep messaging functionality
client = Client(data.twilio_sid, data.twilio_auth_token) 

try:

    # prepare domain activity classifier
    print("\nIGNORE ERROR #################")
    model = load_model('model2.h5')
    print("END IGNORE #################\n")

    # 4 hrs (14,400s) / 10 mins (600s) = 24 rounds
    ROUND_LIMIT = 24
    for i in range(ROUND_LIMIT):
        # reset
        print("\n____RUN %d____" % (i))
        data.now = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        data.print_state()

        # mark start time
        t1 = datetime.now()

        # send me message the run has started
        message = "Run %d started at %s" % (i, data.now)
        client.messages.create(         
            to='+12143648810',
            from_='+19123965665',
            body=message
        ) 


        # take screenshots of each domain
        screenshot_paths = screenshot(data.CURRENT_DOMAIN_ID, data.SHOT_PATH, domains)

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

        print("__Done__")

        # mark end time
        t2 = datetime.now()
        time_spent = (t2 - t1).seconds

        # wait 10 minutes before next run
        while time_spent < 600:
            time.sleep(10)
            t2 = datetime.now()
            time_spent = (t2 - t1).seconds

except Exception as e:
    print(e)

    # send me message the run crashed
    message = "Run has crashed"
    client.messages.create(         
        to='+12143648810',
        from_='+19123965665',
        body=message
    ) 

