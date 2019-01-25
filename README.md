
# I. Descriptive Statistics For "CVE Details" Site

## Parts of the work
### 1) run script scrapProducts.py for scraping products  for each year in the range 1999-2019. This script creates many xslx-files (1999_31_5.xlsx, 1999_36_23.xlsx, ... ) for each products: 

    Number	Product		     Product ID	Vendor ID
    1	Debian Linux Debian      36	    23
    2	Linux Kernel Linux	     47	    33
    4	Mac Os X Apple	         156	49
    8	Ubuntu Linux Canonical	 20550	4781
    12	Windows 7 Microsoft	     17153	26
    15	Opensuse Opensuse	     14195	8184
    17	Windows Vista Microsoft	 9591	26
    22	Windows 10 Microsoft	 32238	26
    23	Windows Xp Microsoft	 739	26
    25	Windows 8.1 Microsoft	 26434	26
    28	Mac Os X Server Apple	 2274	49
    34	Enterprise Linux Redhat	 78	    25
    43	Windows 2000 Microsoft	 107	26
    48	Solaris	SUN	             31	    5

 ### 2) run script createGeneralDF.py. This script creates All_Data_for_Analysis.xlsx from xslx-files (1999_31_5.xlsx, 1999_36_23.xlsx, ... ).
 ### 3) run this jupyter notebook for the analysis. The file All_Data_for_Analysis.xlsx from previous step is input file.
 ### 4) the script userDialog.py produces 1 ouput file for the single product_id, vendor_id, year. For example, this is user dialog during the script running:

    Please enter the year: 2008
    Please enter product_id: 156
    Please enter vender_id: 49
    The file 2008_156_49.xlsx has created
    >>
    
  #### This script gives opportunity to add the new file before combine all xlsx-files to All_Data_for_Analysis.xlsx.

# II. Descriptive Statistics For "CVE Details" Site --- Each Project ID - Vendor ID

## Parts of the work
### 1) run script eachFromGeneral.py for the creating data for each products and all years in the range 1999-2019. This script creates many xslx-files in the folder 'EachProducts': 31_5_for_Analysis.xlsx, 36_23_for_Analysis.xlsx, ...  for each products during all years. 

 
 ### 2) run this jupyter notebook for the analysis. The file All_Data_for_Analysis.xlsx from previous milestone is the input file.
