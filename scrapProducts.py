#python2.7.x compiled on Python 2.7.10 :: Anaconda 2.3.0 (64-bit)
#CveDetailsScaper.py
#A small python script used for scraping the CVE Details website for collating the following information
# CVE-ID,Severity,Product,Vendor,Summary (Primary required fields, many additional fields shall be present)

#https://raw.githubusercontent.com/salecharohit/cve_details_scraper/master/CveDetailsScaper.py
from bs4 import BeautifulSoup
#import requests,pprint,sys,datetime,re
import requests,re

#import requests,pprint,csv,os,datetime,re,urllib2
import pandas as pd
from pandas import ExcelWriter


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
    publishDate.append(dateStr.split("\t")[1 ].split(":")[1]); 
    updateDate.append(dateStr.split("\t")[2 ].split(":")[1])

     
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
    global cveIDNumber
    global summaryText
    global publishDate
    global updateDate
    global softwareType
    global vendor
    global product
    global version
    global cvssScore
    global confidentialityImpact
    global integrityImpact
    global availibilityImpact
    global accessComplexity
    global authentication
    global gainedAccess
    global vulnType
    global exploitAvailible
    
    print ("Start Writing to Excel File : "+fileName)
    data = {'CVE ID Number': cveIDNumber, 'Summary Text': summaryText, 'Publish Date': publishDate,'Update Date': updateDate, 'Software Type': softwareType, 'Vendor': vendor,'Product':product,'Version':version,'CVSS Score':cvssScore,'Confidentiality Impact':confidentialityImpact,'Integrity Impact':integrityImpact,'Availibility Impact':availibilityImpact,'Access Complexity':accessComplexity,'Authentication':authentication,'Gained Access':gainedAccess,'Vulnerability Type':vulnType}
    df = pd.DataFrame(data,columns=['CVE ID Number','Publish Date','Update Date', 'Software Type','Vendor','Product','Version','CVSS Score','Confidentiality Impact','Integrity Impact','Availibility Impact','Access Complexity','Authentication','Gained Access','Vulnerability Type','Summary Text'])
    writer = ExcelWriter(fileName)
    df.to_excel(writer,'CVE Details',index=False)
    writer.save()
    print ("Writing to Excel File : "+fileName)
    
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
    
    
def main():
    
        
    # 1) the list of pairs: (project_id, vendor_id) for 1999-2016
    my_list = [ (36,23), (47, 33), (156, 49), (20550, 4781), (17153, 26), (14195,8184), (9591,26),(32238,26),(739,26), (26434,26), (2274,49),(78    , 25), (107,    26),(31,    5)]
    for year in range(1999,2017):
    
    
    #2) the list of pairs: (project_id, vendor_id) for 2017-2019
    # the pair (36,23) is not avaible for the 2017 and 2018 years    
    
    # my_list = [  (47, 33), (156, 49), (20550, 4781), (17153, 26), (14195,8184), (9591,26),(32238,26),(739,26), (26434,26), (2274,49),(78    , 25), (107,    26),(31,    5)]
    #for year in range(2017,2020):
    
  
    
        for product_id, vender_id in my_list:
         #product_id=input('Please enter product_id: ')
         #vender_id=input('Please enter vender_id: ')
         fileName=str(year) + "_" + str(product_id) + "_" + str(vender_id) + ".xlsx"
         #print("The file " + fileName + " has created")
         fullUrl="http://www.cvedetails.com/vulnerability-list.php?vender_id="+str(vender_id)+"&product_id="+str(product_id)+"&version_id=0&page=0&year="+str(year) #+"&month=0"#+str(month) #+"&order=3"
         
         soupObject=getSoupHTML(fullUrl)
         cvePagesArray=getCVEPages(soupObject)
         try:
             cveArray=[]
             for cvePage in cvePagesArray:
                 #print cvePage
                 soupObject=getSoupHTML(cvePage)
                 getCVEIds(soupObject,cveArray)
                 
             count=0;
             for cve in cveArray:
                 
                     getCVEDetails(cve)
                     count=count+1
                     
         except:
                 continue
         
         try:
             writeToExcel(fileName)

         except:
                 continue
         
    print ("Completed.")
         
             
if __name__ == '__main__':
    status = main()
     
