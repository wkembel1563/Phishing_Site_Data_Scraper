import requests
from bs4 import BeautifulSoup as bs
import time

class Phisherman:

    def __init__(self, start, end):
        self.__start = start
        self.__end = end
        self.__success = 0

    
    def __get_start(self):
        return self.__start

    
    def __set_start(self, start):
        self.__start = start


    def __get_end(self):
        return self.__end


    def __set_end(self, end):
        self.__end = end


    def __make_page_url(self, page):
        return "https://www.phishtank.com/phish_search.php?page={}\
            &active=y&valid=y&Search=Search".format(page)


    def __make_detail_page_url(self, url_id):
        return "https://www.phishtank.com/phish_detail.php?\
            phish_id={}".format(url_id)


    def __get_ids(self, page):
        """GET IDS
        
        gets phishtank ids on selected page of phishtanks active, valid phishing sites
        search page
        
        Parameters
        ----------
        page: (int)
            the page number of the search page on phishtank
            
        Returns
        -------
        url_ids: (list)
            list of phishtank id's on that page'
            
        None
            returns nothing when the phishtank site is down
        
        """

        print("Gathering links from page [{}]... ".format(page), end="")
        response = requests.get(self.__make_page_url(page))

        if response.status_code == 200:
            soup = bs(response.content, "html.parser")
            elements = soup.select(".value:first-child > a")
            url_ids = [element.text for element in elements]
            print("Success")
            return url_ids
        else:
            print("Fail")
            return None


    def __get_data(self, url_id):
        """GET DATA

        gets the url and date added for some phishtank id

        Parameters
        ----------
        url_id: (string)
            a single phishtank id for some url

        Returns
        -------
        (dictionary)
            a dictionary object containing the url and date listed
            on phishtank for the given phishtank id

            "url" and "date" are the keys

            modified to include phishtank id under the "phish_id" key
        """

        print("Gathering data for url [id={}]... ".format(url_id), end="")
        response = requests.get(self.__make_detail_page_url(url_id))

        if response.status_code == 200:
            soup = bs(response.content, "html.parser")

            phish_url = soup.select_one(".padded > div:nth-child(4) > \
                span:nth-child(1) > b:nth-child(1)").text

            date = self.__parse_date_string(soup.select_one(".small").text)
            self.__success += 1
            print("Success")
            file=open("Log_url.txt","a")
            file.write(str(phish_url))
            file.write("\n")
            file1=open("Log_date.txt","a")
            file1.write(str(date))
            file1.write("\n")
            time.sleep(3)
            return {"url": phish_url, "date": date, "phish_id": url_id}
        else:
            
            print("Fail")
            print("Thread sleeping")
            time.sleep(60)
            return None


    def __parse_date_string(self, date_str):
        return " ".join(date_str.split()[1:6])


    def crawl(self):
        """GET DATA

        scrapes phishtank id's from phishtank.org's 'active' 'valid' 
        search page. returns list of dict objects containing url and date for
        each id found

        modified to also return the list of phishtank id's 

        Parameters
        ----------
        ( None )

        Returns
        -------
        data: (list)
            list of dictionary objects indexed by "url" and data"
            modified to inlude phishtank id under "phish_id" key

            contain url and date for each phishtank id scraped from the site
        """
        print("Start crawling! Phisherman is gathering data... ")
        url_ids = []
        data = []
        
        # get list of phishtank id's on selected pages of the active, valid
        # search page
        for page in range(self.start, self.end + 1):
            
            result = self.__get_ids(page)
            
            if result:
                url_ids += result

        # collect data on each phishtank id
        for url_id in url_ids:

            # get url_id's url and date data
            # stored in dictionary object
            result = self.__get_data(url_id)

            if result:
                # thus data is a list of dictionaries
                data.append(result)

        print("Crawling complete! Successfully gathered {} urls".format(
            self.__success))

        return data


    start = property(__get_start, __set_start)
    end = property(__get_end, __set_end)
