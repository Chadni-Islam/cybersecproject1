A Scraper/Parser for AlienVault Blog Pages

Aims to extract the following information: 
 - Title of the threat/malware
 - Relevant names of technologies used
 - Country where the attack occurs
 - Date of the attacks
 - Attack Vectors (how the threat operates)
 - Assets (what the threat targets)
 - Likelihood of attack occuring
 - Severity of the threat
 - Risk factor of threat (Based on likelihood and severity)
 - Maliciousness of threat
 - Indicators of Compromise

Explanation of process:
1. Scrape text from an AlienVault blog page using BeautifulSoup
2. Separate text into paragraphs on different threats (based on the html structure)
3. Extract the title of the paragraph (using html structure)
4. If paragraph is only one sentence long, ignore. Not enough description to extract relevant information
5. If no relevant threat in title, e.g. just 'New Detection Techniques', ignore the paragraph
6. Perform Named Entity Recognition on paragraph using Spacy. 
   - 'ORG' - names of relevant technologies
   - 'GPE' - countries. Due to false positives, check against a list of countries. If not found, classify as 'ORG'
   - 'DATE'
7. If a link is found in the paragraph to the 'Open Threat Exchange', extract indicators of compromise using the OTX api. 
8. Follow the guidelines identified for classifying maliciousness at: www.mitre.org/sites/default/files/pdf/10_2914.pdf. Arbitrarily use keywords, to attempt to detect rules. 
9. Identify keywords which imply attacks or assets through manual analysis of these sentences. Examples found in other/Attack_Asset_examples.csv
10. Scan each sentence in paragraph for these keywords. If hit, records as attack vector/asset. 
11. Use google search API to search the first three nouns/vectors of asset with CAPEC data to find a relevant article. (Searching asset found to have higher accuracy than searching attack vector)
12. Take first capec link found and scrape it to obtain a likelihood and severity rating. 
13. Combine likelihood and severity rating into a risk rating using the rules of the following resource: https://itsecurity.uiowa.edu/resources/everyone/determining-risk-levels

To Do:
 - Improve accuracy of NER
 - Change keywords used to be empirically identified
 - Classify malware type. Potential source: https://www.joesandbox.com/analysispaged/0 (Identifies malware type and a lot of other information but low hit rate on return a result)