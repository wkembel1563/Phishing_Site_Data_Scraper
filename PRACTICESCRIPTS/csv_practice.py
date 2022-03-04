import sys
import socket
import whois
import csv
import ipinfo
import requests
import numpy as np
import pandas as pd

"""
GET FIELD NAMES
"""

df = pd.read_csv("test.csv", na_values=['-', '', 'holder'])
print(df)
arr = df.to_numpy()
print(arr)
print(arr.shape)
	

"""
Get domain data and save as row in csv
"""

"""
# TODO Test data collection. Switch to append
# TODO read last id from file, then append new domain_id
# TODO Check for virus total api acceptance. may go to mavmail
write_mode = 'w'
with open('test.csv', write_mode, newline='') as csvfile: 

	# create csv file columns
	fieldnames = getFieldNames()

	# prepare write object
	writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
	writer.writeheader()

	# save domain data 
	for url in lines:
		# get ip
		try:

			# retrieve data
			ip = socket.gethostbyname(url)
			details = handler.getDetails(ip)
			w = whois.whois(url)

			# save to csv
			writer.writerow({'domain_id':domain_id, 'phish_id':'holder', 'domain_name':url, 'open_code':'', 'virus_total_score':'', 'virus_total_engines':'', 'ip_address':ip, 'ip_country':details.country, 'registrant_country':w.country, 'registrar':w.registrar, 'test':'test'})

			domain_id += 1
		except (socket.gaierror, UnicodeError):
			print("Invalid Domain: %s" % (url))


"""





"""
kaifeng@kaifeng-VirtualBox:~/Desktop$ python3 csv_practice.py 
   domain_id  phish_id         domain_name  ...  registrant_country                     registrar  test
0          1       NaN         www.ign.com  ...                  US   CSC CORPORATE DOMAINS, INC.  test
1          2       NaN      www.apnews.com  ...                  US        Network Solutions, LLC  test
2          3       NaN  www.unsplashed.com  ...                  CZ  GRANSY S.R.O D/B/A SUBREG.CZ  test
3          4       NaN      www.reddit.com  ...                  US             MarkMonitor, Inc.  test

[4 rows x 11 columns]
[[1 nan 'www.ign.com' nan nan nan '151.101.1.135' 'US' 'US'
  'CSC CORPORATE DOMAINS, INC.' 'test']
 [2 nan 'www.apnews.com' nan nan nan '34.96.72.156' 'US' 'US'
  'Network Solutions, LLC' 'test']
 [3 nan 'www.unsplashed.com' nan nan nan '209.126.123.13' 'US' 'CZ'
  'GRANSY S.R.O D/B/A SUBREG.CZ' 'test']
 [4 nan 'www.reddit.com' nan nan nan '151.101.193.140' 'US' 'US'
  'MarkMonitor, Inc.' 'test']]
(4, 11)
"""
"
>>> import numpy as np
>>> import pandas as pd
>>> df = pd.read_csv('test.csv', na_values=['-', '', 'holder'])
>>> print(df)
   domain_id  phish_id         domain_name  ...  registrant_country                     registrar  test
0          1       NaN         www.ign.com  ...                  US   CSC CORPORATE DOMAINS, INC.  test
1          2       NaN      www.apnews.com  ...                  US        Network Solutions, LLC  test
2          3       NaN  www.unsplashed.com  ...                  CZ  GRANSY S.R.O D/B/A SUBREG.CZ  test
3          4       NaN      www.reddit.com  ...                  US             MarkMonitor, Inc.  test

[4 rows x 11 columns]
>>> arr = df.to_numpy()
>>> js = df.to_json()
>>> arr
array([[1, nan, 'www.ign.com', nan, nan, nan, '151.101.1.135', 'US',
        'US', 'CSC CORPORATE DOMAINS, INC.', 'test'],
       [2, nan, 'www.apnews.com', nan, nan, nan, '34.96.72.156', 'US',
        'US', 'Network Solutions, LLC', 'test'],
       [3, nan, 'www.unsplashed.com', nan, nan, nan, '209.126.123.13',
        'US', 'CZ', 'GRANSY S.R.O D/B/A SUBREG.CZ', 'test'],
       [4, nan, 'www.reddit.com', nan, nan, nan, '151.101.193.140', 'US',
        'US', 'MarkMonitor, Inc.', 'test']], dtype=object)

          domain_name                     registrar
0         www.ign.com   CSC CORPORATE DOMAINS, INC.
1      www.apnews.com        Network Solutions, LLC
2  www.unsplashed.com  GRANSY S.R.O D/B/A SUBREG.CZ
>>> dom_num = arr.size[0]
Traceback (most recent call last):
TypeError: 'int' object is not subscriptable
>>> dom_num = arr.shape[0]
>>> dom_num
4
>>> df
   domain_id  phish_id         domain_name  open_code  virus_total_score  virus_total_engines       ip_address ip_country registrant_country                     registrar  test
0          1       NaN         www.ign.com        NaN                NaN                  NaN    151.101.1.135         US                 US   CSC CORPORATE DOMAINS, INC.  test
1          2       NaN      www.apnews.com        NaN                NaN                  NaN     34.96.72.156         US                 US        Network Solutions, LLC  test
2          3       NaN  www.unsplashed.com        NaN                NaN                  NaN   209.126.123.13         US                 CZ  GRANSY S.R.O D/B/A SUBREG.CZ  test
3          4       NaN      www.reddit.com        NaN                NaN                  NaN  151.101.193.140         US                 US             MarkMonitor, Inc.  test
>>> df.loc[dom_num, :] = [5, '', www.test.com, '', '', '', 123.123.321.123, US, US, test.inc, test]
    df.loc[dom_num, :] = [5, '', www.test.com, '', '', '', 123.123.321.123, US, US, test.inc, test]
                                                                  ^
SyntaxError: invalid syntax
>>> df.loc[dom_num, :] = 5, '', www.test.com, '', '', '', 123.123.321.123, US, US, test.inc, test
    df.loc[dom_num, :] = 5, '', www.test.com, '', '', '', 123.123.321.123, US, US, test.inc, test
                                                                 ^
SyntaxError: invalid syntax
>>> df.loc[dom_num, :] = np.array([5, '', www.test.com, '', '', '', 123.123.321.123, US, US, test.inc, test])
    df.loc[dom_num, :] = np.array([5, '', www.test.com, '', '', '', 123.123.321.123, US, US, test.inc, test])
                                                                           ^
SyntaxError: invalid syntax
>>> df.loc[dom_num-1, :] = np.array([5, '', www.test.com, '', '', '', 123.123.321.123, US, US, test.inc, test])
    df.loc[dom_num-1, :] = np.array([5, '', www.test.com, '', '', '', 123.123.321.123, US, US, test.inc, test])
                                                                             ^
SyntaxError: invalid syntax
>>> df.loc[0, 'open_code'] = 'test'
>>> df
   domain_id  phish_id         domain_name open_code  virus_total_score  virus_total_engines       ip_address ip_country registrant_country                     registrar  test
0          1       NaN         www.ign.com      test                NaN                  NaN    151.101.1.135         US                 US   CSC CORPORATE DOMAINS, INC.  test
1          2       NaN      www.apnews.com       NaN                NaN                  NaN     34.96.72.156         US                 US        Network Solutions, LLC  test
2          3       NaN  www.unsplashed.com       NaN                NaN                  NaN   209.126.123.13         US                 CZ  GRANSY S.R.O D/B/A SUBREG.CZ  test
3          4       NaN      www.reddit.com       NaN                NaN                  NaN  151.101.193.140         US                 US             MarkMonitor, Inc.  test
>>> df.loc[dom_num-1, :] = np.array([5, '', 'www.test.com', '', '', '', "123.123.321.123", 'US', 'US', 'test.inc', 'test'])
>>> df
  domain_id phish_id         domain_name open_code virus_total_score virus_total_engines       ip_address ip_country registrant_country                     registrar  test
0         1      NaN         www.ign.com      test               NaN                 NaN    151.101.1.135         US                 US   CSC CORPORATE DOMAINS, INC.  test
1         2      NaN      www.apnews.com       NaN               NaN                 NaN     34.96.72.156         US                 US        Network Solutions, LLC  test
2         3      NaN  www.unsplashed.com       NaN               NaN                 NaN   209.126.123.13         US                 CZ  GRANSY S.R.O D/B/A SUBREG.CZ  test
3         5                 www.test.com                                                  123.123.321.123         US                 US                      test.inc  test
>>> df.loc[dom_num, :] = np.array([5, '', 'www.test.com', '', '', '', '123.123.321.123', 'US', 'US', 'test.inc', 'test'])
>>> df
  domain_id phish_id         domain_name open_code virus_total_score virus_total_engines       ip_address ip_country registrant_country                     registrar  test
0         1      NaN         www.ign.com      test               NaN                 NaN    151.101.1.135         US                 US   CSC CORPORATE DOMAINS, INC.  test
1         2      NaN      www.apnews.com       NaN               NaN                 NaN     34.96.72.156         US                 US        Network Solutions, LLC  test
2         3      NaN  www.unsplashed.com       NaN               NaN                 NaN   209.126.123.13         US                 CZ  GRANSY S.R.O D/B/A SUBREG.CZ  test
3         5                 www.test.com                                                  123.123.321.123         US                 US                      test.inc  test
4         5                 www.test.com                                                  123.123.321.123         US                 US                      test.inc  test
>>> df.to_csv('test.csv')
>>> arr = df.to_numpy()
>>> dom_num = arr.shape[0]
>>> dom_num
5
>>> id = df.loc[dom_num-1, 'domain_id']
>>> id
'5'
>>> quit()
"""
