#python2.7.x compiled on Python 2.7.10 :: Anaconda 2.3.0 (64-bit)
#CveDetailsScaper.py
#A small python script used for scraping the CVE Details website for collating the following information
# CVE-ID,Severity,Product,Vendor,Summary (Primary required fields, many additional fields shall be present)

#https://raw.githubusercontent.com/salecharohit/cve_details_scraper/master/CveDetailsScaper.py
from bs4 import BeautifulSoup
#import requests,pprint,sys,datetime,re
import requests,sys,datetime,re
from argparse import ArgumentParser
#import requests,pprint,csv,os,datetime,re,urllib2
import pandas as pd
from pandas import ExcelWriter
#from pandas import ExcelFile
import calendar

cveIDNumber=[]
summaryText=[]
publishDate=[]
updateDate=[]
softwareType=[]
vendor=[]
product=[]
version=[]
cvssScore=[]
confidentialityImpact=[]
integrityImpact=[]
availibilityImpact=[]
accessComplexity=[]
authentication=[]
gainedAccess=[]
vulnType=[]
exploitAvailible=[]

confidentialityImpactTup=('Complete','None','Partial')
integrityImpactTup=('Complete','None','Partial')
availibilityImpactTup=('Complete','None','Partial')
accessComplexityTup=('Low','Medium','High') #Low means , accessible easily.
authenticationRequiredTup=('Not Required','Single System') #Single System implies that attacker requires a session.
accessLevelGainedTup=('None','Admin') #What is the access Level gained by exploiting this vulnerability


def getSoupHTML(url):
	response=requests.get(url)
	html=response.content
	soup = BeautifulSoup(html,"html.parser")
	#pprint.pprint(soup)
	return soup

def getCVEIds(soup,cveArray):
	table = soup.find('table',attrs={'class','searchresults'})
	for a in table.find_all('a',href=True):
		m = re.search("CVE-\d{4}-\d{4,7}",a['href'])
		if m:
			cveArray.append(m.group(0))
		
def getCVEPages(soup):
	cveIDPages=[]
	items=soup.find_all('div',class_="paging")
	for item in items:
		links=item.find_all('a')
		for link in links:
			cveIDPages.append("http://www.cvedetails.com/"+str(link['href']))
	
	return cveIDPages

	
def getCVEDetails(cveid=''):
	cveUrl='http://www.cvedetails.com/cve/'+cveid+'/'
	response = requests.get(cveUrl)
	cveHtml=response.content
	soup = BeautifulSoup(cveHtml,"html.parser")
	if soup =='':
		return
	cveIDNumber.append(cveid)
	table = soup.find(id='vulnprodstable')
	cvssTable = soup.find(id='cvssscorestable')
	summarySoup=soup.find('div',class_="cvedetailssummary")
	summaryText.append(summarySoup.text.split("\n")[1])
	dateStr=summarySoup.text.split("\n")[3]; 
	publishDate.append(dateStr.split("\t")[1 ].split(":")[1]); updateDate.append(dateStr.split("\t")[2 ].split(":")[1])

     
	productData=[]
	for row in table.findAll('tr')[::-1]: #Get only the last row
		cols=row.findAll('td')
		for i in range(len(cols)):
			productData.append(cols[i].text.strip())	
	softwareType.append(productData[1])
	vendor.append(productData[2])
	product.append(productData[3])
	version.append(productData[4])
	cvssData=[]
	for row in cvssTable.findAll('tr'): #Get only the first row
		cols=row.findAll('td')
		for i in range(len(cols)):
			cvssData.append(cols[i].text.strip())			
	#pprint.pprint(cvssData)
	cvssScore.append(cvssData[0])
	ci=cvssData[1].split("\n")[0]
	confidentialityImpact.append(ci)
	ii=cvssData[2].split("\n")[0]
	integrityImpact.append(ii)
	ai=cvssData[3].split("\n")[0]
	availibilityImpact.append(ai)
	ac=cvssData[4].split("\n")[0]
	accessComplexity.append(ac)
	ar=cvssData[5].split("\n")[0]
	authentication.append(ar)
	al=cvssData[6].split("\n")[0]
	gainedAccess.append(al)
	vulnType.append(cvssData[7])
	
def writeToExcel(fileName=''):
	print ("Writing to Excel File : "+fileName)
	data = {'CVE ID Number': cveIDNumber, 'Summary Text': summaryText, 'Publish Date': publishDate,'Update Date': updateDate, 'Software Type': softwareType, 'Vendor': vendor,'Product':product,'Version':version,'CVSS Score':cvssScore,'Confidentiality Impact':confidentialityImpact,'Integrity Impact':integrityImpact,'Availibility Impact':availibilityImpact,'Access Complexity':accessComplexity,'Authentication':authentication,'Gained Access':gainedAccess,'Vulnerability Type':vulnType}
	df = pd.DataFrame(data,columns=['CVE ID Number','Publish Date','Update Date', 'Software Type','Vendor','Product','Version','CVSS Score','Confidentiality Impact','Integrity Impact','Availibility Impact','Access Complexity','Authentication','Gained Access','Vulnerability Type','Summary Text'])
	writer = ExcelWriter(fileName)
	df.to_excel(writer,'CVE Details',index=False)
	writer.save()
	#print ("Completed.")
	
def main():
    while(True):
         year=input('Please enter the year: ')
         product_id=input('Please enter product_id: ')
         vender_id=input('Please enter vender_id: ')
         fileName=year + "_" + product_id + "_" + vender_id + ".xlsx"
         
         fullUrl="http://www.cvedetails.com/vulnerability-list.php?vender_id="+str(vender_id)+"&product_id="+str(product_id)+"&version_id=0&page=0&year="+str(year) #+"&month=0"#+str(month) #+"&order=3"
         
         soupObject=getSoupHTML(fullUrl)
         cvePagesArray=getCVEPages(soupObject)
         
         cveArray=[]
         for cvePage in cvePagesArray:
             #print cvePage
             soupObject=getSoupHTML(cvePage)
             getCVEIds(soupObject,cveArray)
             
         count=0;
         for cve in cveArray:
             #try:
                 getCVEDetails(cve)
                 count=count+1
                 #if(count==200):
                 #   break
                 #print ("Getting Details for CVE ID: "+cve+". Completed "+str(count)+" Out of "+str(len(cveArray)))
             #except:
             #    continue
         
          
         writeToExcel(fileName)
         print("The file " + fileName + " has created")
         again=input('Do you want to continue (y/n)? ')
         if again=='n':
             break
             
              
    

if __name__ == '__main__':
    status = main()
     
