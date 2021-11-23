from androguard.core.bytecodes import apk, dvm
from androguard.core.analysis import analysis
import re
import pandas as pd
import os
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score


# unique features in all ben-mal files
all_perm_uni = []     
all_intent_uni = []
all_hardware_uni = []
all_providers_uni = []
all_recievers_uni = []
all_services_uni = []

# features in all ben files
all_perm_ben = []     
all_intent_ben = []
all_hardware_ben = []
all_providers_ben = []
all_recievers_ben = []
all_services_ben = []

# features in all mal files
all_perm_mal = []     
all_intent_mal = []
all_hardware_mal = []
all_providers_mal = []
all_recievers_mal = []
all_services_mal = []


apps_ben =  os.listdir(r'C:\Users\rahul\Desktop\Mohit\betch project\Benign apk')
apps_mal = os.listdir(r'C:\Users\rahul\Desktop\Mohit\betch project\Malware apk')

'''def get_permissions(path):
  app = apk.APK(path)
  perms = app.get_permissions()  
  for p in perms:
    if p not in all_perm_uni:
          all_perm_uni.append(p)
  return perms

def add_intent(inte,app,itemtype, name):
    
    for action,intent_name in app.get_intent_filters(itemtype, name).items():
        for intent in intent_name:
                inte.append(intent)
                if intent not in all_intent_uni:
                     all_intent_uni.append(intent)
                   
    return inte

def get_intent(path):
    app = apk.APK(path)
    inte = []
    activities = app.get_activities()
    activitiesString = 'activity'
    for activity in activities:
        add_intent(inte,app,activitiesString, activity)
    services = app.get_services()
    serviceString = 'service'
    for service in services:
        add_intent(inte,app,serviceString, service)
    receivers = app.get_receivers()
    receiverString = 'receiver'
    for receiver in receivers:
        add_intent(inte,app,receiverString, receiver)      
    
    return inte

def get_hardware(path):
    app = apk.APK(path)
    hardware  = app.get_features()

    for h in hardware:
        if h not in all_hardware_uni:
            all_hardware_uni.append(h)
    
    return hardware

def get_contentProvider(path):
    app = apk.APK(path)
    provider = app.get_providers()

    for p in provider:
        if p not in all_providers_uni:
            all_providers_uni.append(p)

    return provider

def get_receivers(path):
    app = apk.APK(path)
    receivers = app.get_receivers()

    for r in receivers:
        if r not in all_recievers_uni:
            all_recievers_uni.append(r)

    return receivers

def get_services(path):
    app = apk.APK(path)
    services = app.get_services()

    for s in services:
        if s not in all_services_uni:
            all_services_uni.append(s) 
    
    return services

#extracting benign apps features

c = 0
for file in apps_ben:
    path = "C:\\Users\\rahul\\Desktop\\Mohit\\betch project\\Benign apk\\" + file
    a = "int "+file
    print(a)
    all_recievers_ben.append(get_receivers(path))
    all_services_ben.append(get_services(path))
    all_providers_ben.append(get_contentProvider(path))
    all_hardware_ben.append(get_hardware(path))
    all_perm_ben.append(get_permissions(path))
    a = "perm "+file
    print(a)
    all_intent_ben.append(get_intent(path))   
    c=c+1
    print(c)

#print malware apps features

c = 0
print("MAL")
for file in apps_mal:
    a = "perm "+file
    print(a)
    path = "C:\\Users\\rahul\\Desktop\\Mohit\\betch project\\Malware apk\\" + file
    all_perm_mal.append(get_permissions(path))    
    all_intent_mal.append(get_intent(path))
    a = "int "+file
    print(a)
    all_hardware_mal.append(get_hardware(path))
    all_providers_mal.append(get_contentProvider(path))
    all_recievers_mal.append(get_receivers(path))
    all_services_mal.append(get_services(path))
    c = c+1
    print(c)


#converting features to csv
print("permission")
benign_Perm_data = pd.DataFrame(index=apps_ben)
malware_Perm_data = pd.DataFrame(index=apps_mal)

for i in all_perm_uni:
    col=[]
    for j in all_perm_ben:
        if i in j:
            col.append(1)
        else:
            col.append(0)
    benign_Perm_data[i] = col

    col=[]
    for j in all_perm_mal:
        if i in j:
            col.append(1)
        else:
            col.append(0)
    malware_Perm_data[i] = col

benign_Perm_data.to_csv(r'C:\Users\rahul\Desktop\Mohit\betch project\benign_Perm_data.csv', index_label='Id')
malware_Perm_data.to_csv(r'C:\Users\rahul\Desktop\Mohit\betch project\malware_Perm_data.csv', index_label='Id')

print("intent")
benign_intent_data = pd.DataFrame(index=apps_ben)
malware_intent_data = pd.DataFrame(index=apps_mal)

for i in all_intent_uni:
    col = []
    for j in all_intent_ben:
        if i in j:
            col.append(1)
        else:
            col.append(0)
    benign_intent_data[i] = col

    col=[]
    for j in all_intent_mal:
        if i in j:
            col.append(1)
        else:
            col.append(0)
    malware_intent_data[i] = col


malware_intent_data.to_csv(r'C:\Users\rahul\Desktop\Mohit\betch project\malware_intent_data.csv', index_label='Id') 
benign_intent_data.to_csv(r'C:\Users\rahul\Desktop\Mohit\betch project\benign_intent_data.csv', index_label='Id')

print("hardware components")
benign_hardware_data = pd.DataFrame(index=apps_ben)
malware_hardware_data = pd.DataFrame(index=apps_mal)

for i in all_hardware_uni:
    col = []
    for j in all_hardware_ben:
        if i in j:
            col.append(1)
        else:
            col.append(0)
    benign_hardware_data[i] = col
    col=[]
    for j in all_hardware_mal:
        if i in j:
            col.append(1)
        else:
            col.append(0)
    malware_hardware_data[i] = col


malware_hardware_data.to_csv(r'C:\Users\rahul\Desktop\Mohit\betch project\malware_hardware_data.csv', index_label='Id')
benign_hardware_data.to_csv(r'C:\Users\rahul\Desktop\Mohit\betch project\benign_hardware_data.csv', index_label='Id')

print("content providers")
benign_provider_data = pd.DataFrame(index=apps_ben)
malware_provider_data = pd.DataFrame(index=apps_mal)

for i in all_providers_uni:
    col = []
    for j in all_providers_ben:
        if i in j:
            col.append(1)
        else:
            col.append(0)
    benign_provider_data[i] = col
    col=[]
    for j in all_providers_mal:
        if i in j:
            col.append(1)
        else:
            col.append(0)
    malware_provider_data[i] = col


malware_provider_data.to_csv(r'C:\Users\rahul\Desktop\Mohit\betch project\malware_provider_data.csv', index_label='Id')
benign_provider_data.to_csv(r'C:\Users\rahul\Desktop\Mohit\betch project\benign_provider_data.csv', index_label='Id')

print("recievers")
benign_recievers_data = pd.DataFrame(index=apps_ben)
malware_recievers_data = pd.DataFrame(index=apps_mal)

for i in all_recievers_uni:
    col = []
    for j in all_recievers_ben:
        if i in j:
            col.append(1)
        else:
            col.append(0)
    benign_recievers_data[i] = col
    col = []
    for j in all_recievers_mal:
        if i in j:
            col.append(1)
        else:
            col.append(0)
    malware_recievers_data[i] = col


malware_recievers_data.to_csv(r'C:\Users\rahul\Desktop\Mohit\betch project\malware_recievers_data.csv', index_label='Id')
benign_recievers_data.to_csv(r'C:\Users\rahul\Desktop\Mohit\betch project\benign_recievers_data.csv', index_label='Id')

print("services")
benign_services_data = pd.DataFrame(index=apps_ben)
malware_services_data = pd.DataFrame(index=apps_mal)

for i in all_services_uni:
    col = []
    for j in all_services_ben:
        if i in j:
            col.append(1)
        else:
            col.append(0)
    benign_services_data[i] = col
    col = []
    for j in all_services_mal:
        if i in j:
            col.append(1)
        else:
            col.append(0)
    malware_services_data[i] = col

malware_services_data.to_csv(r'C:\Users\rahul\Desktop\Mohit\betch project\malware_services_data.csv', index_label='Id')
benign_services_data.to_csv(r'C:\Users\rahul\Desktop\Mohit\betch project\benign_services_data.csv', index_label='Id')
'''

dfb = pd.read_csv(r'C:\Users\rahul\Desktop\Mohit\betch project\benign_Perm_data.csv', index_col='Id')
dfm = pd.read_csv(r'C:\Users\rahul\Desktop\Mohit\betch project\malware_Perm_data.csv', index_col='Id')

all_perm_uni = list(dfm.columns)
apps_ben = list(dfb.index)
apps_mal = list(dfm.index)

sorted_inc = []
sorted_dec = []

for k in range(0, 6):
    rank = pd.Series()
    print(k)
    for j in all_perm_uni:
        sumB = 0
        sumM = 0
        for i in apps_ben:
            sumB += dfb.loc[i,j]
        for i in apps_mal:
            sumM += dfm.loc[i,j]
        
         # Use permisssions with support 0%, 5%, 10%, 15%, ..., 50%
        if sumB >= (k)*0.05*len(apps_ben) and sumM >= (k)*0.05*len(apps_mal):
            fB = sumB / len(apps_ben)
            fM = sumM / len(apps_mal)
            rank[j] = (fM - fB)
    
    inc_rank = rank.sort_values()
    dec_rank = rank.sort_values(ascending=False)
    sorted_inc.append(inc_rank)
    sorted_dec.append(dec_rank)
    df_dec = pd.DataFrame(sorted_dec)
    df_dec.to_csv(r'C:\Users\rahul\Desktop\Mohit\betch project\dec.csv')

