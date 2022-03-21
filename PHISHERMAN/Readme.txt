
###### Purpose ########

- store url, date added and phishtank id for each url listed on the phishtank.org 
active, valid phish site search page

#######################



###### How to Execute ##########

- Enter the following command:

	python3 crawl.py [start phishtank page] [end phishtank page]

* the start/end arguments are the page numbers for phishtanks active, valid
phishing domain search page. page 0 has the most recent entries

################################



##### Output #######

- log.csv: holds data for all the urls that have ever been scraped with this tool
- new.csv: holds most recent, new url data added to the log from the last scrape

* if data scraped from the site is already present in the log.csv file, it will be deleted from 
the set of scraped data before writing to these files

####################


