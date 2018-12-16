# Named Entity Recognintion on Alien Vault blog posts
# Scrapes info about malware/threats from page and attempts to extract threat data
import utils
import spacy
import pandas as pd
import csv
from bs4 import BeautifulSoup
import requests
import pprint
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
from googleapiclient.discovery import build


# Initialise nlp corpus
nlp = spacy.load('en_core_web_sm')

# Google api key and search engine id
my_api_key = 'AIzaSyAVfCR6inp74mBkr7w12TVLH3l4vkWwsiw'
my_cse_id = '003774403560526411905:wsb8ncz3hw4'

# Performs google search using google custom search API
def google_search(search_term, api_key, cse_id, **kwargs):
    service = build("customsearch", "v1", developerKey=api_key)
    res = service.cse().list(q=search_term, cx=cse_id, **kwargs).execute()
    return res['items']

# initialise Open Threat Exchange API
otx = OTXv2("1bc976440bad33a81703fcec442f158153fe93976770874ea1af79680a84f0c7")

# open a list of countries
f = open("other/country.csv", "rb")

# Keywords to detect if attack vector or asset
# Add space in front of try so it isn't picked up as a part of a word
attackKeys = ["attacker", "trick", " try ", " tries ", "attempt", "launch"]
assetKeys = ["result", "ability", "grant", "installation", "corrupt", "poison", "after ", "information"]

# Get some blog pages
links = utils.getAlienVaultPage(3)
otxurl = "https://otx.alienvault.com/pulse/"

for link in links:
	# Scrape blog page
	text = utils.scrapeAlienVault(link)

	# Information we can extract
	title = []				# Extracted from TITLE
	rawtext = []			# Raw paragraph text, so accuracy can be checked
	names = []				# NER - ORG
	country = []			# NER - GPE
	date = []				# NER - DATE
	attackvectors = []		# Attack Vectors (found with keywords)
	assets = []				# Assets (found with keywords)
	capeclink = []			# CAPEC Article found (to see accuraccy)
	likelihood = []			# Obtain from CAPEC
	severity = []			# Obtain from CAPEC
	risk = []				# Obtain from likelihood and severity
	maliciousness = []		# 1 - least, 5 - maximum
	indicators = []			# For now extracted from OTX links

	# Extracting csv name
	temp = link.split('-')
	csvName = temp[-5] + '-' + temp[-4] + '-' + temp[-3] + '-' + temp[-2] + '-' + temp[-1] + ".csv"

	# Iterates through pparagraphs of blog post
	for count, t in enumerate(text):
		# Create a list of sentences abstraction
		sents = t.split(". ")
		# Ignore paragraphs with only one sentence
		if len(sents) < 3:
			continue

		# TITLE
		# Extracting title based on delimeters
		temp = t.split('%')[0]
		temp = temp.split('-')
		# If no '-', then no relevant title/category (for now)
		if len(temp) == 1:
			continue
		else:
			title.append(temp[-1])

		# Cut title, perform nlp
		t = t.split('%')[1]
		doc = nlp(t)

		# Append Raw text
		rawtext.append(t)

		# NAMES COUNTRIES DATES
		# Extracting names/countries/dates
		tempN, tempC, tempD = "", "", ""
		for X in doc.ents:
			# Threat name
			if X.label_ == 'ORG':
				# Ignoring 'Open Threat Exchange'
				if (X.text == "Open Threat Exchange"):
					continue
				tempN += X.text + ', '
			# Country/Area
			elif X.label_ == 'GPE':
				# Check that entity is actually a country
				isCountry = False
				for row in f:
					row = str(row)
					if X.text.lower() in row.lower():
						isCountry = True
						tempC += row.split(",")[2] + ' '
				# Else not a country, so assume ORG
				if not isCountry:
					tempN += X.text + ', '
			# Date
			elif X.label_ == 'DATE':
				tempD += X.text + ', '
		names.append(tempN)
		country.append(tempC)
		date.append(tempD)

		# INDICATORS
		# Extracting OTX links for indicators
		if (otxurl in t):
			pulseID = t.split(otxurl)[-1]
			tempI = ""
			# Get all indicators for a specific pulse
			results = otx.get_pulse_indicators(pulseID)
			for count, indicator in enumerate(results):
				# Only get first 5 for now, some have too many
				if count > 5:
					break
				tempI += indicator["indicator"] + " (" + indicator["type"] + ")\n"
			indicators.append(tempI)
		else:
			indicators.append("")

		# MALICIOUSNESS
		# Identify maliciousness by keywords which follow mitre rules from: www.mitre.org/sites/default/files/pdf/10_2914.pdf
		malic = 0
		key2 = ["target", "data", "information", "access"]
		key3 = ["backdoor", "install"]
		key4 = ["military", "government", "nation", "defense", "defence"]
		for k in key2:
			if k in t:
				malic = 2
				break
		for k in key3:
			if k in t:
				malic = 3
				break
		for k in key4:
			if k in t:
				malic += 1
				break
		# If still 0, couldn't identify
		if malic == 0:
			malic = '-'
		maliciousness.append(malic)

		# ATTACKVECTORS ASSETS LIKELIHOOD SEVERITY
		asses = ""
		attacks = ""
		caplink = ""
		likeli = ""
		sev = ""
		# iterate through sentences
		for i in sents:
			# apply nlp
			doc = nlp(i)

			# Iterate through attack keywords
			for j in attackKeys:
				# If keyword in sentence
				if j in i.lower():
					# Iterate through nlp tokens
					for count, token in enumerate(doc):
						# Only keep nouns and verbs
						if token.pos_ == "NOUN" or token.pos_ == "VERB":
							attacks += token.text + ' '
					# Break after first keyword found
					break

			# Iterate through asset keywords
			for j in assetKeys:
				# if keyword in sentence
				if j in i.lower():
					short = ""		# A shorter version of the sentence
					# Iterate through nlp tokens
					c = 0
					for count, token in enumerate(doc):
						# Only keep nouns and verbs
						if token.pos_ == "NOUN" or token.pos_ == "VERB":
							asses += token.text + ' '
							c += 1
							# Only take 3 for best search results
							if c < 4:
								short += token.text + ' '

					# Search for a CAPEC resource
					query = "capec.mitre.org " + short
					res = google_search(query, my_api_key, my_cse_id, num=10)
					# Get first relevant link
					for r in res: 
						# Only take capec data definitions
						if "capec.mitre.org/data/definition" in r['link']:
							caplink = r['title']
							# Get page
							page = requests.get(r['link'])
							soup = BeautifulSoup(page.text, 'html.parser')
							# Take first two detail parameters
							for count, rf in enumerate(soup.find_all(id="Detail")):
								tex = rf.find('p')
								if count == 0:
									try:
										likeli = tex.get_text()
									except AttributeError:
										pass
								elif count == 1:
									try:
										sev = tex.get_text()
									except AttributeError:
										pass
								else:
									break
							break
					break
		attackvectors.append(attacks)
		assets.append(asses)
		capeclink.append(caplink)
		likelihood.append(likeli)
		severity.append(sev)

		# RISK
		# Calculated from likelihood and severity
		# Options Very Low, Low, Medium, High, Very High 
		# Risk Matrix taken from https://itsecurity.uiowa.edu/resources/everyone/determining-risk-levels
		ris = ""
		if ((sev == "Very Low") or (sev == "Low" and (likeli == "Medium" or likeli == "Low" or likeli == "Very Low")) or (sev == "Medium" and likeli == "Very Low")):
			ris = "Low"
		elif ((sev == "Low" and (likeli == "Very High" or likeli == "High")) or (sev == "Medium" and (likeli == "High" or likeli == "Medium" or likeli == "Low")) or (sev == "High" and (likeli == "Medium" or likeli == "Low" or likeli == "Very Low")) or (sev == "Very High" and (likeli == "Low" or likeli == "Very Low"))):
			ris = "Medium"
		elif ((sev == "Medium" and likeli == "Very High") or (sev == "High" and (likeli == "Very High" or likeli == "High")) or (sev == "Very High" and (likeli == "Very High" or likeli == "High" or likeli == "Medium"))):
			ris = "High"
		risk.append(ris)


	# Combine data into a pandas dataframe
	ThreatInfo = pd.DataFrame({
		"Title": title,
		"RawText": rawtext,
		"Names": names,
		"Country": country,
		"Date": date,
		"Attack Vectors": attackvectors,
		"Assets": assets,
		"Likelihood": likelihood,
		"Severity": severity,
		"Risk": risk,
		"Maliciousness": maliciousness,
		"Indicators": indicators
		})
	ThreatInfo.to_csv("output/3/" + csvName, encoding='utf-8', columns=["Title", "RawText", "Date", "Names", "Country", "Attack Vectors", "Assets", "Likelihood", "Severity", "Risk", "Maliciousness", "Indicators"])
