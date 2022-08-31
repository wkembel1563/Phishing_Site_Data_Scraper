# Phishing_Site_Data_Scraper
Resource used to scrape and organize data from phishing sites and various API's such as VirusTotal for the purpose of analyzing phishing site activity over time.

This was integrated into a larger project with the goal of reliably identifying and reporting zombie domains in the wild.

## Explanation of Files 

timed_run.py
- This script controls the entire system and is run at regular intervals via cron jobs
- It loads a list of identified phishing sites from an external directory (not included here but was present during system use) then proceeds to visit each site using the selenium firefox webdriver, take a screenshot, and log various data about the cite using internal functionality and API's
- The collected data was logged in a file in CSV

parsedomains.py
- This file contains helper functions used by timed_run.py to collect data on the phishing sites

cert.lock and phish.lock
- These were used as semaphores to prevent simultaneous execution of the system when two cron jobs overlapped due to slow processing

model.h5 and model2.h5
- These are two versions of a phishing site activity CNN classifier
- They take a screenshot of a website as input, and they output the probability that the site is active or inactive (404)
- model2.h2 has better performance and outperformed the python requests module in classification accuracy

geckodriver
- This is the driver file needed for the selenium automated browsing tool to take screenshots of phishing sites automatically
