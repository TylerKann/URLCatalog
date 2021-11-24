import numpy as np 
import csv
from urllib.request import urlopen
import pandas as pd
import whois # pip install python-whois
import dns.resolver

serverPort = "443"

file_name = "SiteList.csv"
output_file = "FinalProcessed.csv"
df = pd.read_csv(file_name, delimiter = ',')
df.drop_duplicates(subset=None, inplace=True)
''' 
OLD ALPHANUM
AlphaNum = {'a': 0, 'b': 0, 'c': 0, 'd':0, 'e':0, 'f':0, 'g': 0, 'h': 0, 'i':0, 'j':0, 'k':0, 'l': 0, 'm': 0,
		    'n':0, 'o':0, 'p':0, 'q': 0, 'r': 0, 's':0, 't':0, 'u':0, 'v': 0, 'w': 0, 'x':0, 'y':0, 'z':0,
		    '0': 0, '1': 0, '2':0, '3':0, '4':0, '5': 0, '6': 0, '7':0, '8':0, '9':0, '-': 0, '.': 0, '_':0,
		     ':':0, '/':0, '?':0, '=':0, '&':0, '%':0, '#':0, '@':0, ';':0, '(':0, ')':0, '+':0, '\'':0, ',':0, '~':0, '*':0, '[':0, ']':0, '!':0, '$':0, ' ':0} # this is a list of all valid chars in a domain (base list)
'''
# This one is only valid domain chars, above one was all valid URL chars
AlphaNum = {'a': 0, 'b': 0, 'c': 0, 'd':0, 'e':0, 'f':0, 'g': 0, 'h': 0, 'i':0, 'j':0, 'k':0, 'l': 0, 'm': 0,
		    'n':0, 'o':0, 'p':0, 'q': 0, 'r': 0, 's':0, 't':0, 'u':0, 'v': 0, 'w': 0, 'x':0, 'y':0, 'z':0,
		    '0': 0, '1': 0, '2':0, '3':0, '4':0, '5': 0, '6': 0, '7':0, '8':0, '9':0, '-': 0, '.': 0, '_':0} # this is a list of all valid chars in a domain (base list)




urls = df.iloc[:,0] # grab all the URLS (0th column all rows)
newData = []

COLS = ['Num'] + ['Inception', 'Expiration', 'Updated', 'Name Servers', 'Auth Servers', 'SSL Cert'] + list(key for key in AlphaNum.keys()) + ['Site Type']
print(COLS)
newDF = pd.DataFrame(columns = COLS)
 

def registered_and_date(domain_name):
    """
    A function that returns dates if registered (more to come?) and discards otherwise 
    """
    try:
        w = whois.whois(domain_name)

    except Exception:
    	# not registered (cannot use)
        return [0]
    else:
        # we want when the site was created
        if not ((w.creation_date) and (w.name_servers) and (w.expiration_date) and (w.updated_date)): 
        	return [0] 
        if type(w.creation_date) == list: 
        	inception = w.creation_date[0].year
        else: 
        	inception = w.creation_date.year
        if type(w.expiration_date) == list: 
        	expiration = w.expiration_date[0].year
        else: 
        	expiration = w.expiration_date.year 
        if type(w.updated_date) == list: 
        	update = w.updated_date[0].year
        else: 
        	update = w.updated_date.year 
        if type(w.name_servers) == list: 
        	servers = len(w.name_servers)
        else: 
        	servers = 1


        return [inception, expiration, update, servers] # years should be good enough 

def AuthResults(domain_name): 
	try: 
		ans = dns.resolver.resolve(domain_name)
	except (dns.resolver.NoAnswer,dns.resolver.NXDOMAIN,dns.resolver.NoNameservers,dns.exception.Timeout) as e:
		return [] # we cant use this site, not information 
	else: 
		return [len(ans)] # returning how many authoritative results it has (small server maybe less safe) 


def getCert(domain_name): 
	serverAddress = (domain_name, serverPort);
	try: 
		cert = ssl.get_server_certificate(serverAddress);
	except: 
		return [0] # no ssl cert 
	else: 
		return [1] # has a cert 


def url_data(domain_name):
	ANList = AlphaNum.copy() # make a copy of it for this specific url 
	url = str.lower(domain_name) # upper case and lower case function the same for domain name 
	for char in url: 
		if char in ANList:
			ANList[char] += 1 # increment the counter when we count a  char 
	listForm = np.asarray(list(ANList.values())) # this will convert the dict into string (e.g. aaaa.com -> [4, 0, 1... ])
	return listForm





j = 0

for i in range(len(urls)):
	if i % 100 == 0:
		print(f"urls processed: {i}")
		print(f"urls kept: {j}")
	if i % 20 == 0: 
		newDF.to_csv(output_file, index = False) 
		print("Backup Complete")
	url = urls[i] 
	dates =	registered_and_date(url) # first we try who-is 
	if (len(dates) == 1): # 1 output means we got a failure 
		continue  # we dont want this data in new file 
	A = AuthResults(url)
	if (len(A) == 0): # no length means there was no data (failure)
		continue 
	cert =  getCert(url) # by this point we should hope that we have an active site 
	urlData = url_data(url) # getting meta data of the url (character breakdown) 

	finalOutput = np.concatenate(([[i], dates, A, cert, urlData, [df.iloc[i,1]]])) # this adds on the Y value that we ultimately want to predict 
	mergeDF = pd.DataFrame([finalOutput], columns = COLS)
	#newDF = newDF.merge(mergeDF, how = 'outer')
	newDF = newDF.append(mergeDF)
	j += 1

print(f"{j*100/len(urls)} % of URLS kept")
newDF.to_csv(output_file, index=False)
