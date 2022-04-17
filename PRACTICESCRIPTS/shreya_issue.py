#!/usr/bin/env python3

# read in dfCert
# read in CertInfo

"""
dfCert

dfCertInfo

dflog

for each row in dfCert
    if the url in that row is in dflog urls
        <do sth>
"""

dflog_urls = list(logdf.URL)

dfcert_urls = list(dfCertCSV.URL)

for url in dfcert_urls:
    if url in dflog_urls:
        <do sth>
