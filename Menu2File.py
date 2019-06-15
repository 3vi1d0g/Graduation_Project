import os
import json

with open('./VBOX/Win7_Tample/7.json',mode='r') as file11:
    with open('./KVM/Win7_Tample/7.json', mode='r') as file22:
        jsA = json.load(file11)
        jsB = json.load(file22)
        Li1 = open('Peoce1.json','w+')
        Li2 = open('Peoce2.json','w+')
        List_API_JSA = []
        List_API_JSB = []
        for List_all_apiA in jsA['behavior']['processes'][0]['calls']:
           #List_API_JSA.append(List_all_apiA['api'])
            Li1.write(List_all_apiA['api']+' ')
        for List_all_apiB in jsB['behavior']['processes'][0]['calls']:
            #List_API_JSB.append(List_all_apiB['api'])
            Li2.write(List_all_apiB['api']+' ')
        print 'Finally'