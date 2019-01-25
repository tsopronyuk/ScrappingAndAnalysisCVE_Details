# -*- coding: utf-8 -*-
"""
Created on Fri Jan 11 09:37:10 2019

@author: a1
"""
import pandas as pd
import numpy as np
from pandas import ExcelWriter


#create data for analysis (from all xlsx-files)
list_of_dfs=[]


product_vender=[]
choices = ['low', 'medium', 'high']

my_list = [ (36,23), (47, 33), (156, 49), (20550, 4781), (17153, 26), (14195,8184), (9591,26),(32238,26),(739,26), (26434,26), (2274,49),(78	, 25), (107,	26),(31,	5)]
for year in range(1999,2020):         
        for product_id, vender_id in my_list:
             
             fileName=str(year) + "_" + str(product_id) + "_" + str(vender_id) + ".xlsx"
             
             try:
                 dataframe=pd.read_excel(fileName, "CVE Details")
             except:
                 continue
             
             if(len(dataframe.index) == 0):
                 continue
             
             
             # assigning that filename as a new column in the dataframe
             dataframe['filename'] = fileName
             
             # assigning that product_vender as a new column in the dataframe
             dataframe['product_vender'] = str(product_id) + "_" + str(vender_id)
             
             #print(len(dataframe.columns))
             # convert columns type  of a DataFrame
             dataframe['Publish Date'] = pd.to_datetime(dataframe['Publish Date'])
             dataframe['Update Date'] = pd.to_datetime(dataframe['Update Date'])
             dataframe['CVSS Score'] = pd.to_numeric(dataframe['CVSS Score'])
             
             #new column
             dataframe['days']=dataframe['Update Date'] - dataframe['Publish Date']
             
             
             #classify it, 0-3.9 is low, 4-6.9 is medium, and 7-10 is high
             conditions = [
                 (dataframe['CVSS Score'] > 0) & (dataframe['CVSS Score'] <= 3.9),
                 (dataframe['CVSS Score'] > 3.9) & (dataframe['CVSS Score'] <= 6.9),
                 (dataframe['CVSS Score'] > 6.9) & (dataframe['CVSS Score'] <= 10)]
                 
             #new colum
             dataframe['score level']=np.select(conditions, choices, default='unknown')
             
             #print(dataframe.shape[0])
             
             #remove coluns 6,8,...,15
             #dataframe.drop(dataframe.columns[[6, 8, 9, 10, 11, 12, 13, 14, 15]], axis=1, inplace=True)  # df.columns is zero-based pd.Index 
             
             dataframe.sort_values('Publish Date', inplace=True)             
             
             #print(dataframe.head())
             list_of_dfs.append(dataframe)


  
# Combine a list of dataframes, on top of each other
df = pd.concat(list_of_dfs, ignore_index=True)
df['year'] = df['Publish Date'].dt.year
print(len(df.index))
print(df.head())

writer = ExcelWriter('All_Data_for_Analysis.xlsx')
df.to_excel(writer,'CVE Details',index=False)
writer.save() 
print ("Writing to Excel File : All_Data_for_Analysis.xlsx.")

    