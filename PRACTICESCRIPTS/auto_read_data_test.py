#!/usr/bin/env python3
import pandas as pd
import os
from datetime import date


def updateUrls(source_url_dir, file_to_update, max_num_urls):
    """UPDATE URLS

    gets updated url data from splab_phish_urls, adds to url file

    stops adding to the url file if it contains more than max_num_urls

    """

    """
    check if sayaks url file for day exists/has been updated/is correct day
        create filename based on the current date

        if the file exists, grab each line and extract data

            if there are more commas than needed, ignore line

            otherwise, grab data and check if it exists in collected_urls

            if so, add too file
    if so, read in each line, checking for extra commas
    """
    # don't update if collected urls exceeds max number
    collector_exists = False
    collected_urls = []
    try:
        if os.path.exists(file_to_update):
            collector_exists = True
            df = pd.read_csv(file_to_update)
            if len(df) >= max_num_urls:
                print("Url file is full. Skipping update...")
                return

            collected_urls = list(df.url)

    except Exception as e:
        print("UPDATE URL ERROR: collection file read error")
        print(e)
        exit(1)

    # check url source for new urls
    ## build path using date: mmddyyyy.csv
    today = date.today()
    day = str(today.day)
    month = str(today.month)
    year = str(today.year)
    if len(day) == 1:
        day = '0' + day
    if len(month) == 1:
        month = '0' + month
    source_file = month + day + year + ".csv"
    source_file_path = os.path.join(source_url_dir, source_file)

    ## check each row, skip rows with urls containing commas
    if os.path.exists(source_file_path):
        # extract urls
        with open(source_file_path, "r") as f:
            lines = f.readlines()

            # header contains proper num of commas for each row
            num_of_separators = lines[0].count(',')
            header = lines.pop(0)

            # add header to collection file if its new
            try:
                c_file = open(file_to_update, "a+")
            except Exception as e:
                print("UPDATE URL ERROR: Cannot open url collection file")
                print(e)
                exit(1)
            if not collector_exists:
                c_file.write(header)

            # extract urls from each row
            for line in lines:
                if line.count(',') > num_of_separators:
                    continue

                # find url btw 2nd comma and newline
                comma1 = line.find(',') + 1
                comma2 = line.find(',', comma1, -1) + 1
                url = line[comma2:-1]

                # add to url to collection if url is unique
                if url not in collected_urls:
                    c_file.write(line)

    else:
        print("URL UPDATE: %s does not exist, cannot update urls." % (source_file_path))


if __name__ == "__main__":
    BASE_PATH = os.path.dirname(os.path.realpath(__file__))
    phish_url_dir = os.path.join(BASE_PATH, '../splab_phish_urls/output/')
    cert_url_dir = os.path.join(BASE_PATH, '../splab_phish_urls/output_2/')
    ###############################

    ############################### URL FILES
    collected_phish_url_file = os.path.join(BASE_PATH, 'URLFILES/phish_urls.csv')
    collected_cert_url_file = os.path.join(BASE_PATH, 'URLFILES/cert_urls.csv')
    ###############################

    updateUrls(phish_url_dir, collected_phish_url_file, max_num_urls=10)
    updateUrls(cert_url_dir, collected_cert_url_file, max_num_urls=10)
