from bs4 import BeautifulSoup
import requests
import re

# Extracts only the most significant text from a page
# Returns a string
def scrapePage(url):
	# Download page
	page = requests.get(url)
	pagetext = page.text.encode('ascii', 'ignore')
	soup = BeautifulSoup(pagetext, 'html.parser')

	# Find all paragraphs
	paragraphs = soup.find_all('p')
	# Find all list items
	lists = soup.find_all('li')
	# Find all table entries
	tables = soup.find_all('td')

	text = ""

	# Iterate through all text printing any of notable length
	rawtext = paragraphs + lists + tables
	for t in rawtext:
		if len(t.get_text()) > 15:
			text += t.get_text().encode('ascii', 'ignore') + ' '

	return text

# Extracts an AlienVaultPage from the blog contents page
def getAlienVaultPage(num):
	# Download blog contents page
	page = requests.get("https://www.alienvault.com/forums/categories/usm-anywhere-alienvault-threat-intelligence-update")
	soup = BeautifulSoup(page.text, 'html.parser')

	# Store blog post links in a list
	links = []

	# Iterate through links until we have the desired amount
	for count, a in enumerate(soup.find_all(class_="Title")):
		if (count == num):
			return links

		links.append(a['href'])

	return links


# More targeted version of scrape page which uses knowledge of alienvault div classes
# Returns a list of paragraphs w/ headings
def scrapeAlienVault(url):
	# Download page
	page = requests.get(url)
	pagetext = page.text
	soup = BeautifulSoup(pagetext, 'html.parser')
	# Page content stored in 'Message' class
	soup = soup.find(class_="Message")

	# Paragraphs are headed with 'h3' and contain a list
	headers = soup.find_all('h3')
	#paragraphs = soup.find_all('p')
	lists = soup.find_all('ul')

	docs = [""] * len(headers)

	#print(str(len(docs)) + ' ' + str(len(headers)) + ' ' + str(len(paragraphs)) + ' ' + str(len(lists)))

	# Iterate through paragraphs, appending to docs
	for i in range(len(headers)):
		# Append header to doc
		docs[i] += headers[i].get_text() + ' % '

		# Keep appending siblings (<p>) until we get to next header
		iterater = headers[i]	# Iterator variable
		# Stop when we get to the next header tag
		while("<h" not in str(iterater.next_sibling)):
			# Update iterator
			iterater = iterater.next_sibling
			if iterater is None:
				break

			# If sibling is a list, append list points individually
			if ("<ul" in str(iterater)):
				# Grab the list
				points = lists[i].select('li')
				for j in points:
					docs[i] += ' ' + j.get_text().lower() + '.'

			# Else append the paragraph text
			else:
				# ignore navigable string's
				try:
					docs[i] += ' ' + iterater.get_text()
				except AttributeError:
					pass

		# Clean unicode
		docs[i] = docs[i].replace(u'\xa0', u' ')


	return docs

# Get every bit of text
def url_to_string(url):
    res = requests.get(url)
    html = res.text
    soup = BeautifulSoup(html, 'html.parser')
    for script in soup(["script", "style", 'aside']):
        script.extract()
    return " ".join(re.split(r'[\n\t]+', soup.get_text()))