import sys
import os
import csv
import pandas as pd
from pandas.errors import EmptyDataError


def save_csv(data, path, write_mode):

    print("Writing data to [{}]... ".format(path), end="")

    with open(path, write_mode, newline='') as csvfile:
        fieldnames = ['url', 'date', 'phish_id']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        if write_mode == 'w':
            writer.writeheader()

        for item in data:
            writer.writerow(item)

    print("Done")


def process_args():

    try:
        start = int(sys.argv[1])
        end = int(sys.argv[2])
    except:
        print("Warning! No agruments entered, reverting to defaults")
        start = 0
        end = 0

    return start, end


def remove_duplicate_urls(data, filename, data_type): 
    """REMOVE DUPLICATE URLS

    removes elements from data object if their url string is already present
    in the CSV file

    Parameters
    ----------
    data: (n/a)
        the data object in containing information on each url

        containers currently supported: dictionary

    filename: (string)
        of CSV file which will be checked for existing records

    data_type: (string)
        defines which kind of the object the data parameter is

    Returns
    -------
    ( None )
    """
    # generate path to file
    path_to_file = os.getcwd()
    full_path = path_to_file + '/' + filename

    # extract csv data
    try:
        df = pd.read_csv(full_path)
    except EmptyDataError:
        print("%s is empty. No duplicates to remove." % (filename))
        return None

    # remove duplicate urls from data object
    to_remove = []
    if data_type == "dictionary":
        csv_urls = df.loc[:,"url"]
        
        # find duplicate urls 
        for item in data:
            for url in csv_urls:
                if item["url"] == url:
                    to_remove.append(url)
                    break

        # remove duplicates urls
        for url in to_remove:
            for item in data:
                if item["url"] == url:
                    print("%s already present in csv file.\nDeleting from scraped data...\n" % (url))
                    data.remove(item)
                    break
