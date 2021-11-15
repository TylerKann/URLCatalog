import numpy as np 
import csv
from urllib.request import urlopen
import pandas as pd

'''
Creates list of websites into CSV. 
To update, add url into URLS array and add the following descriptor 

0 - LEGIT 
1 - PHISHING 
2 - MALWARE 

and add a following indicator 

0 - URL 
1 - TXT 
'''

URLS = np.array([["https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt", 1, "URL"],
				["https://openphish.com/feed.txt", 1, "URL"],
				["ALL-phishing-domains.txt", 1, "TXT"],
				["https://raw.githubusercontent.com/mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites/master/.input_sources/hacked-malware-websites.txt", 2, "URL"],
				["https://gist.githubusercontent.com/elimisteve/69077a93d21b8bf8a02a362c830fbcb1/raw/beb74077e1186c5cf2a4e79fd7c6b3c3d67f664f/safe-alexa500.txt", 0, "URL"]])


q = 0
file_name = "PhishingCSV.csv"
with open(file_name, 'w', newline='') as file:
    writer = csv.writer(file)

    for i in range(np.size(URLS,0)):
    	print(URLS[i][0]) 
    	if(URLS[i][2] == "URL"):
	    	site = urlopen(URLS[i][0])
	    	for line in site: 
	    		q += 1
    			url = line.decode("utf-8")
    			writer.writerow([url, URLS[i][1]])
    	else: 
    		with open(URLS[i][0], encoding='UTF-8') as site:
    			for line in site: 
    				q += 1
    				url = line # bytes(line, 'utf-8').decode("utf-8")
    				writer.writerow([url, URLS[i][1]])

df = pd.read_csv(file_name)
l1  = df.shape
df.drop_duplicates(subset=None, inplace=True)
l2 = df.shape)
df.to_csv(file_name, index=False)
print("Removed " + str(l2 - l1) + " duplicates")