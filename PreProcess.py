import numpy as np 
import csv
from urllib.request import urlopen
import pandas as pd


file_name = "SiteList.csv"
output_file = "ProcessedData.csv"
df = pd.read_csv(file_name, delimiter = ',')

urls = df.iloc[:,0] # grab all the URLS (0th column all rows)
newData = []
AlphaNum = {'a': 0, 'b': 0, 'c': 0, 'd':0, 'e':0, 'f':0, 'g': 0, 'h': 0, 'i':0, 'j':0, 'k':0, 'l': 0, 'm': 0,
		    'n':0, 'o':0, 'p':0, 'q': 0, 'r': 0, 's':0, 't':0, 'u':0, 'v': 0, 'w': 0, 'x':0, 'y':0, 'z':0,
		    '0': 0, '1': 0, '2':0, '3':0, '4':0, '5': 0, '6': 0, '7':0, '8':0, '9':0, '-': 0, '.': 0, '_':0,
		     ':':0, '/':0, '?':0, '=':0, '&':0, '%':0, '#':0, '@':0, ';':0, '(':0, ')':0, '+':0, '\'':0, ',':0, '~':0, '*':0, '[':0, ']':0, '!':0, '$':0, ' ':0} # this is a list of all valid chars in a domain (base list)


for i in range(len(urls)):
	ANList = AlphaNum.copy() # make a copy of it for this specific url 
	url = urls[i] 
	url = str.lower(url) # upper case and lower case function the same for domain name 
	for char in url: 
		ANList[char] += 1 # increment the counter when we count a  char 
	listForm = np.asarray(list(ANList.values())) # this will convert the dict into string (e.g. aaaa.com -> [4, 0, 1... ])
	finalOutput = np.concatenate(([listForm, [df.iloc[i,1]]])) # this adds on the Y value that we ultimately want to predict 
	newData.append(finalOutput)


dfNew = pd.DataFrame(newData)
dfNew.to_csv(output_file, index=False)
