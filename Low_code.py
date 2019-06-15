#!/usr/bin/python
import json
import os
#This is path of kvm!!
kvm_win7_cn = "./KVM/Win7_CN"
kvm_win7_en = "./KVM/Win7_EN"
kvm_win_xp = "./KVM/Win_XP"
#This is path of vbox!!
vbox_win7_cn = "./VBOX/Win7_CN"
vbox_win7_en = "./\VBOX/Win7_EN"
vbox_win_xp = "./VBOX/Win_XP"
#This is path of vm!!
vm_win7_cn = "./VM/Win7_CN"
vm_win7_en = "./VM/Win7_EN"
vm_win_xp = "./VM/Win_XP"

kvm_win7_cn_files = os.listdir(kvm_win7_cn)
kvm_win7_en_files = os.listdir(kvm_win7_en)
kvm_win_xp_files = os.listdir(kvm_win_xp)
vbox_win7_cn_files = os.listdir(vbox_win7_cn)
vbox_win7_en_files = os.listdir(vbox_win7_en)
vbox_win_xp_files = os.listdir(vbox_win_xp)
vm_win7_cn_files = os.listdir(vm_win7_cn)
vm_win7_en_files = os.listdir(vm_win7_en)
vm_win_xp_file = os.listdir(vm_win_xp)

#敏感黑名单API，后续可以添加
Black_APIs=['ReleaseDC','GetSystemMetrics','GetDC','GetDeviceCaps','GetDiskFreeSpaceExA','GetDriveTypeA','GetEnvironmentVariableA','GetLastError',' GetLogicalDrives','GetSystemDefaultLangID',
            ' GetTickCount','Process32NextW','IsDebuggerPresent','Process32FirstW']


#1.No consideration of multi-processes!
#2.Comparison between the two File!
#纵向比对，参数为（文件1，平台1，文件2，平台2）
def Cross_Check(file1,file1_plat,file2,file2_plat):
    print 'Tample:'
    jsA = json.load(file1)
    jsB = json.load(file2)
    print jsA['target']['file']['name']
    Flag_NULL_A = 0
    Flag_NULL_B = 0
    #Step one :check behavior //
	#通过TRY来判断是否又行为
    print '-----------------------------------------'
    print '||         Check the behavior          ||'
    print '-----------------------------------------'
    try :
        a = jsA['behavior']
        Flag_NULL_A = 1#标志标识有行为
    except:
        print "The Sample's Behaviors is NULL in",file1_plat
        Flag_NULL_A = 0#标志标识没有行为
    try :
        a = jsB['behavior']
        Flag_NULL_B = 1
    except:
        print "The Sample's Behaviors is NULL in",file2_plat
        Flag_NULL_B = 0
    #Can't capture behavior
    if Flag_NULL_A == Flag_NULL_B and Flag_NULL_A == 0:
        print "Can't capture the Sample's behavior ,maybe it have Escaping behavior..."
        print ' '
        print '-----------------------------------------'
        print '||         Check Import APIs           ||'
        print '-----------------------------------------'
        print "There are some APIs in Sample maybe can detect environment ..."
        Import_numA = -1
        Import_numB = -1
        while 1:
            try :
                a=jsA['static']['pe_imports'][Import_numA+1]
                Import_numA = Import_numA+1
            except:
                break
        while 1:
            try :
                a=jsB['static']['pe_imports'][Import_numB+1]
                Import_numB = Import_numB+1
            except:
                break
        if Import_numA == -1 and Import_numB == -1:
            print "Can't read Sample's IAT...The Sample not run or use assembly language."
        else:
            if Import_numA != -1 and Import_numB == -1:
                print "The sample can escape from plat", file2_plat
                temp = 0
                while Import_numA >= 0:
                    try :
                        if jsA['static']['pe_imports'][Import_numA]['imports'][temp]['name'] in Black_APIs:
                            print jsA['static']['pe_imports'][Import_numA]['imports'][temp]['name']
                        temp = temp+1
                    except:
                        temp = 0
                        Import_numA =Import_numA-1
            else:
                if Import_numA == -1:
                    print "The sample can escape from plat", file1_plat
                temp = 0
                while Import_numB >= 0:
                    try:
                        if jsB['static']['pe_imports'][Import_numB]['imports'][temp]['name'] in Black_APIs:
                            print jsB['static']['pe_imports'][Import_numB]['imports'][temp]['name']
                        temp = temp + 1
                    except:
                        temp = 0
                        Import_numB = Import_numB - 1
        print '......I cant analyze it,It seems to detect something and hide itself......'
        return 0
    #Can capture this behavior
    #first ,read the summary ??
    print '         Having detected behavior'
    print ' '
    print '-----------------------------------------'
    print '||            Check Summary            ||'
    print '-----------------------------------------'
    jsAcmplist=[]
    jsBcmplist=[]
    try:
        a = jsA['behavior']['generic'][1]
        print 'More Process!!!!'
    except:
        print 'Only One Process!!!'
    try:
        a=jsA['behavior']['generic'][0]['summary']
        for summary_value in jsA['behavior']['generic'][0]['summary'].values():
            for tamp_value in summary_value :
                jsAcmplist.append(tamp_value)
    except:
        a=0
    try:
        a=jsB['behavior']['generic'][0]['summary']
        for summary_value in jsB['behavior']['generic'][0]['summary'].values():
            for tamp_value in summary_value :
                jsBcmplist.append(tamp_value)
    except:
        a=0
    tmp=0
    if len(jsAcmplist) == 0:
        print 'No summary in',file1_plat
        if len(jsBcmplist) == 0:
            print  'No summary in',file2_plat
    else:
        for xxx in jsAcmplist:
            if xxx not in jsBcmplist:
                print xxx,"  Can't be finded in",file2_plat
                tmp = 1
        for xxx in jsBcmplist:
            if xxx not in jsAcmplist:
                print xxx,"  Can't be finded in",file1_plat
                tmp = 1
        jsAcmplist = []
        jsBcmplist = []
    if tmp == 0:
        print '              Summary Same'
    #second check API's type and number
    print ' '
    print '-----------------------------------------'
    print '||         Check APIs called           ||'
    print '-----------------------------------------'
    jsA_proID = jsA['behavior']['apistats'].keys()[0]
    jsB_proID = jsB['behavior']['apistats'].keys()[0]
    jsA_api_name = jsA['behavior']['apistats'][str(jsA_proID)].keys()
    jsB_api_name = jsB['behavior']['apistats'][str(jsB_proID)].keys()
    List_sameapi_diff_time = []
    Flag_api_Diff = 0    #1 diff / 0 same
    for jsaapi in jsA_api_name:
        if jsaapi not in jsB_api_name:
            print 'API: ',jsaapi,'     --Not in ',file2_plat
            Flag_api_Diff = 1
        else:
            if jsA['behavior']['apistats'][str(jsA_proID)][jsaapi] != jsB['behavior']['apistats'][str(jsB_proID)][jsaapi]:
                List_sameapi_diff_time.append(jsaapi)       #List API name
                print 'API: ',jsaapi,'    --Diff...'
    for jsaapi in jsB_api_name:
        if jsaapi not in jsA_api_name:
            print 'API: ',jsaapi,'     --Not in ',file1_plat
            Flag_api_Diff = 1
    #Check API's sequence and find diff point:
    #First.api same
    print '-----------------------------------------'
    print '||         Check APIs Paras            ||'
    print '-----------------------------------------'
    if Flag_api_Diff == 0 :
        Dict_jsA = {}
        Dict_jsB = {}
        for name_tm in List_sameapi_diff_time:
            Dict_jsA.update({name_tm:{}})
            Dict_jsB.update({name_tm:{}})
        for calls_0_dictA in jsA['behavior']['processes'][0]['calls']:  #This jsA api_dict_para
            if calls_0_dictA['api'] in Dict_jsA.keys():
                for calls_0_apiparaA in calls_0_dictA['arguments'].keys():
                    if Dict_jsA[calls_0_dictA['api']].has_key(calls_0_apiparaA) == False:   #Dict_jsA has no keys
                        Dict_jsA[calls_0_dictA['api']].update({calls_0_apiparaA:[]})
                        Dict_jsA[calls_0_dictA['api']][calls_0_apiparaA].append(calls_0_dictA['arguments'][calls_0_apiparaA])
                    else:#Dict_jsA has keys
                        Dict_jsA[calls_0_dictA['api']][calls_0_apiparaA].append(calls_0_dictA['arguments'][calls_0_apiparaA])
        for calls_0_dictB in jsB['behavior']['processes'][0]['calls']:  #This jsB api_dict_para
            if calls_0_dictB['api'] in Dict_jsB.keys():
                for calls_0_apiparaB in calls_0_dictB['arguments'].keys():
                    if Dict_jsB[calls_0_dictB['api']].has_key(calls_0_apiparaB) == False:   #Dict_jsB has no keys
                        Dict_jsB[calls_0_dictB['api']].update({calls_0_apiparaB:[]})
                        Dict_jsB[calls_0_dictB['api']][calls_0_apiparaB].append(calls_0_dictB['arguments'][calls_0_apiparaB])
                    else:#Dict_jsB has keys
                        Dict_jsB[calls_0_dictB['api']][calls_0_apiparaB].append(calls_0_dictB['arguments'][calls_0_apiparaB])
        #print Dict_jsA
        tmp = 0
        print '-----D0wn is Point +++ Para----'
        print '     Para 0nly in','-',file1_plat,'-'
        for APIname in Dict_jsA.keys():
            print '#',APIname,':'
            for APIpara in Dict_jsA[APIname]:
                print '   ##',APIpara,':'
                for APIparavalue in Dict_jsA[APIname][APIpara]:
                    if APIparavalue not in Dict_jsB[APIname][APIpara]:
                        print '       ',APIparavalue
                        tmp = 1
        print ' '
        print '     Para 0nly in', '-', file2_plat, '-'
        for APIname in Dict_jsB.keys():
            print '#', APIname,':'
            for APIpara in Dict_jsB[APIname]:
                print '   ##', APIpara,':'
                for APIparavalue in Dict_jsB[APIname][APIpara]:
                    if APIparavalue not in Dict_jsA[APIname][APIpara]:
                        print '       ', APIparavalue
                        tmp = 1
        if tmp == 0:
            print ' '
            print '......Sample performance is the same on the contrast platform......'
            print '......Reason:1.They all show evasive behavior.   2.None of them showed evasive behavior......'
            print '......Please improve the experimental platform, or build a physical machine......'
        else:
            print '......This divergence point seems to be caused by different API parameters......'
        #return 0
    #API diff ,so we will check the squence ,Then check diff point and thier para
    else:
        print ' '
        print '-----------------------------------------'
        print '||         Check APIs Sqens            ||'
        print '-----------------------------------------'
        List_API_JSA = []
        List_API_JSB = []
        for List_all_apiA in jsA['behavior']['processes'][0]['calls']:
            List_API_JSA.append(List_all_apiA['api'])
        for List_all_apiB in jsB['behavior']['processes'][0]['calls']:
            List_API_JSB.append(List_all_apiB['api'])
        List_API_JSA_len=len(List_API_JSA)
        List_API_JSB_len=len(List_API_JSB)
        print List_API_JSA_len,file1_plat
        print List_API_JSB_len,file2_plat
        Sq_A=0
        Sq_B=0
        Sq_A_Down = List_API_JSA_len -1    #jsA mowei
        Sq_B_Down = List_API_JSB_len -1   #jsB mowei
        if List_API_JSA_len <= List_API_JSB_len:
            while Sq_A != List_API_JSA_len-1:   #Front divergence point
                if List_API_JSA[Sq_A] == List_API_JSB[Sq_B]:
                    Sq_A=Sq_A+1
                    Sq_B=Sq_B+1
                    continue
                else:
                    if List_API_JSA[Sq_A] == List_API_JSB[Sq_B+1] and List_API_JSB[Sq_B] == List_API_JSA[Sq_A+1]:
                        Sq_A=Sq_A+2
                        Sq_B=Sq_B+2
                        continue
                    else:
                        break
            while Sq_A_Down > Sq_A:    #Backward divergence point
                if List_API_JSA[Sq_A_Down] == List_API_JSB[Sq_B_Down]:
                    Sq_A_Down = Sq_A_Down - 1
                    Sq_B_Down = Sq_B_Down - 1
                    continue
                else:
                    if List_API_JSA[Sq_A_Down] == List_API_JSB[Sq_B_Down-1] and List_API_JSB[Sq_B_Down] == List_API_JSA[Sq_A_Down-1]:
                        Sq_A_Down = Sq_A_Down - 2
                        Sq_B_Down = Sq_B_Down - 2
                        continue
                    else:
                        break
            print 'The point of divergence seems:' + file1_plat
            print '3.' + jsA['behavior']['processes'][0]['calls'][Sq_A + 3]['api']
            print jsA['behavior']['processes'][0]['calls'][Sq_A + 3]['arguments']
            print ' '
            print '2.' + jsA['behavior']['processes'][0]['calls'][Sq_A + 2]['api']
            print jsA['behavior']['processes'][0]['calls'][Sq_A + 2]['arguments']
            print ' '
            print '1.' + jsA['behavior']['processes'][0]['calls'][Sq_A + 1]['api']
            print jsA['behavior']['processes'][0]['calls'][Sq_A + 1]['arguments']
            print ' '
            print '0.' + jsA['behavior']['processes'][0]['calls'][Sq_A]['api']
            print jsA['behavior']['processes'][0]['calls'][Sq_A]['arguments']
            print ' '
            print '-1.' + jsA['behavior']['processes'][0]['calls'][Sq_A - 1]['api']
            print jsA['behavior']['processes'][0]['calls'][Sq_A - 1]['arguments']
            print ' '
            print '-2.' + jsA['behavior']['processes'][0]['calls'][Sq_A - 2]['api']
            print jsA['behavior']['processes'][0]['calls'][Sq_A - 2]['arguments']
            print ' '
            print '-3.' + jsA['behavior']['processes'][0]['calls'][Sq_A - 3]['api']
            print jsA['behavior']['processes'][0]['calls'][Sq_A - 3]['arguments']
            print ' '
            print '-4.' + jsA['behavior']['processes'][0]['calls'][Sq_A - 4]['api']
            print jsA['behavior']['processes'][0]['calls'][Sq_A - 4]['arguments']
            print ' '
            print '-5.' + jsA['behavior']['processes'][0]['calls'][Sq_A - 5]['api']
            print jsA['behavior']['processes'][0]['calls'][Sq_A - 5]['arguments']
            print ' '
            print '-6.' + jsA['behavior']['processes'][0]['calls'][Sq_A - 6]['api']
            print jsA['behavior']['processes'][0]['calls'][Sq_A - 6]['arguments']
            print ' '
            print '-7.' + jsA['behavior']['processes'][0]['calls'][Sq_A - 7]['api']
            print jsA['behavior']['processes'][0]['calls'][Sq_A - 7]['arguments']
            print '---------------------------------------------------------------'
            print 'The point of divergence seems:' + file2_plat
            print '3.' + jsB['behavior']['processes'][0]['calls'][Sq_B + 3]['api']
            print jsB['behavior']['processes'][0]['calls'][Sq_B + 3]['arguments']
            print ' '
            print '2.' + jsB['behavior']['processes'][0]['calls'][Sq_B + 2]['api']
            print jsB['behavior']['processes'][0]['calls'][Sq_B + 2]['arguments']
            print ' '
            print '1.' + jsB['behavior']['processes'][0]['calls'][Sq_B + 1]['api']
            print jsB['behavior']['processes'][0]['calls'][Sq_B + 1]['arguments']
            print ' '
            print '0.' + jsB['behavior']['processes'][0]['calls'][Sq_B]['api']
            print jsB['behavior']['processes'][0]['calls'][Sq_B]['arguments']
            print ' '
            print '-1.' + jsB['behavior']['processes'][0]['calls'][Sq_B - 1]['api']
            print jsB['behavior']['processes'][0]['calls'][Sq_B - 1]['arguments']
            print ' '
            print '-2.' + jsB['behavior']['processes'][0]['calls'][Sq_B - 2]['api']
            print jsB['behavior']['processes'][0]['calls'][Sq_B - 2]['arguments']
            print ' '
            print '-3.' + jsB['behavior']['processes'][0]['calls'][Sq_B - 3]['api']
            print jsB['behavior']['processes'][0]['calls'][Sq_B - 3]['arguments']
            print ' '
            print '-4.' + jsB['behavior']['processes'][0]['calls'][Sq_B - 4]['api']
            print jsB['behavior']['processes'][0]['calls'][Sq_B - 4]['arguments']
            print ' '
            print '-5.' + jsB['behavior']['processes'][0]['calls'][Sq_B - 5]['api']
            print jsB['behavior']['processes'][0]['calls'][Sq_B - 5]['arguments']
            print ' '
            print '-6.' + jsB['behavior']['processes'][0]['calls'][Sq_B - 6]['api']
            print jsB['behavior']['processes'][0]['calls'][Sq_B - 6]['arguments']
            print ' '
            print '-7.' + jsB['behavior']['processes'][0]['calls'][Sq_B - 7]['api']
            print jsB['behavior']['processes'][0]['calls'][Sq_B - 7]['arguments']
            # This is shit.
            print '^^^^^^^^^^^^^^^^',file1_plat,Sq_A,'to',Sq_A_Down,'^^^^^^^^^^^^^^^^'
            print '^^^^^^^^^^^^^^^^',file2_plat,Sq_B,'to',Sq_B_Down,'^^^^^^^^^^^^^^^^'
            print ''
            if Sq_A == Sq_A_Down:
                print file2_plat,'_Diff_Action_:'
                while Sq_B <= Sq_B_Down:
                    print jsB['behavior']['processes'][0]['calls'][Sq_B]['api']
                    Sq_B=Sq_B+1
            else:
                print file1_plat, '_Diff_Action_:'
                while Sq_A <= Sq_A_Down:
                    print jsA['behavior']['processes'][0]['calls'][Sq_A]['api']
                    Sq_A = Sq_A + 1
            return

        else:
            while Sq_B != List_API_JSB_len-1:#Front divergence point
                if List_API_JSA[Sq_A] == List_API_JSB[Sq_B]:
                    Sq_A=Sq_A+1
                    Sq_B=Sq_B+1
                    continue
                else:
                    if List_API_JSB[Sq_B] == List_API_JSA[Sq_A+1] and List_API_JSA[Sq_A] == List_API_JSB[Sq_B+1]:
                        Sq_A=Sq_A+2
                        Sq_B=Sq_B+2
                        continue
                    else:
                        break
            while Sq_B_Down > Sq_B:#Backward divergence point
                if List_API_JSB[Sq_B_Down] == List_API_JSA[Sq_A_Down]:
                    Sq_A_Down = Sq_A_Down - 1
                    Sq_B_Down = Sq_B_Down - 1
                    continue
                else:
                    if List_API_JSB[Sq_B_Down] == List_API_JSA[Sq_A_Down-1] and List_API_JSA[Sq_A_Down] == List_API_JSB[Sq_B_Down-1]:
                        Sq_A_Down = Sq_A_Down - 2
                        Sq_B_Down = Sq_B_Down - 2
                        continue
                    else:
                        break
            print 'The point of divergence seems:' + file2_plat
            print '3.' + jsB['behavior']['processes'][0]['calls'][Sq_B + 3]['api']
            print jsB['behavior']['processes'][0]['calls'][Sq_B + 3]['arguments']
            print ' '
            print '2.' + jsB['behavior']['processes'][0]['calls'][Sq_B + 2]['api']
            print jsB['behavior']['processes'][0]['calls'][Sq_B + 2]['arguments']
            print ' '
            print '1.' + jsB['behavior']['processes'][0]['calls'][Sq_B + 1]['api']
            print jsB['behavior']['processes'][0]['calls'][Sq_B + 1]['arguments']
            print ' '
            print '0.' + jsB['behavior']['processes'][0]['calls'][Sq_B]['api']
            print jsB['behavior']['processes'][0]['calls'][Sq_B]['arguments']
            print ' '
            print '-1.' + jsB['behavior']['processes'][0]['calls'][Sq_B - 1]['api']
            print jsB['behavior']['processes'][0]['calls'][Sq_B - 1]['arguments']
            print ' '
            print '-2.' + jsB['behavior']['processes'][0]['calls'][Sq_B - 2]['api']
            print jsB['behavior']['processes'][0]['calls'][Sq_B - 2]['arguments']
            print ' '
            print '-3.' + jsB['behavior']['processes'][0]['calls'][Sq_B - 3]['api']
            print jsB['behavior']['processes'][0]['calls'][Sq_B - 3]['arguments']
            print ' '
            print '-4.' + jsB['behavior']['processes'][0]['calls'][Sq_B - 4]['api']
            print jsB['behavior']['processes'][0]['calls'][Sq_B - 4]['arguments']
            print ' '
            print '-5.' + jsB['behavior']['processes'][0]['calls'][Sq_B - 5]['api']
            print jsB['behavior']['processes'][0]['calls'][Sq_B - 5]['arguments']
            print ' '
            print '-6.' + jsB['behavior']['processes'][0]['calls'][Sq_B - 6]['api']
            print jsB['behavior']['processes'][0]['calls'][Sq_B - 6]['arguments']
            print ' '
            print '-7.' + jsB['behavior']['processes'][0]['calls'][Sq_B - 7]['api']
            print jsB['behavior']['processes'][0]['calls'][Sq_B - 7]['arguments']
            print '---------------------------------------------------------------'
            print 'The point of divergence seems:' + file1_plat
            print '3.' + jsA['behavior']['processes'][0]['calls'][Sq_A + 3]['api']
            print jsA['behavior']['processes'][0]['calls'][Sq_A + 3]['arguments']
            print ' '
            print '2.' + jsA['behavior']['processes'][0]['calls'][Sq_A + 2]['api']
            print jsA['behavior']['processes'][0]['calls'][Sq_A + 2]['arguments']
            print ' '
            print '1.' + jsA['behavior']['processes'][0]['calls'][Sq_A + 1]['api']
            print jsA['behavior']['processes'][0]['calls'][Sq_A + 1]['arguments']
            print ' '
            print '0.' + jsA['behavior']['processes'][0]['calls'][Sq_A]['api']
            print jsA['behavior']['processes'][0]['calls'][Sq_A]['arguments']
            print ' '
            print '-1.' + jsA['behavior']['processes'][0]['calls'][Sq_A - 1]['api']
            print jsA['behavior']['processes'][0]['calls'][Sq_A - 1]['arguments']
            print ' '
            print '-2.' + jsA['behavior']['processes'][0]['calls'][Sq_A - 2]['api']
            print jsA['behavior']['processes'][0]['calls'][Sq_A - 2]['arguments']
            print ' '
            print '-3.' + jsA['behavior']['processes'][0]['calls'][Sq_A - 3]['api']
            print jsA['behavior']['processes'][0]['calls'][Sq_A - 3]['arguments']
            print ' '
            print '-4.' + jsA['behavior']['processes'][0]['calls'][Sq_A - 4]['api']
            print jsA['behavior']['processes'][0]['calls'][Sq_A - 4]['arguments']
            print ' '
            print '-5.' + jsA['behavior']['processes'][0]['calls'][Sq_A - 5]['api']
            print jsA['behavior']['processes'][0]['calls'][Sq_A - 5]['arguments']
            print ' '
            print '-6.' + jsA['behavior']['processes'][0]['calls'][Sq_A - 6]['api']
            print jsA['behavior']['processes'][0]['calls'][Sq_A - 6]['arguments']
            print ' '
            print '-7.' + jsA['behavior']['processes'][0]['calls'][Sq_A - 7]['api']
            print jsA['behavior']['processes'][0]['calls'][Sq_A - 7]['arguments']
            # This is shit.
            print '^^^^^^^^^^^^^^^^', file1_plat, Sq_A, 'to', Sq_A_Down,'^^^^^^^^^^^^^^^^'
            print '^^^^^^^^^^^^^^^^', file2_plat, Sq_B, 'to', Sq_B_Down,'^^^^^^^^^^^^^^^^'
            print ''
            if Sq_A == Sq_A_Down:
                print file2_plat, '_Diff_Action_:'
                while Sq_B <= Sq_B_Down:
                    print jsB['behavior']['processes'][0]['calls'][Sq_B]['api']
                    Sq_B = Sq_B + 1
            else:
                print file1_plat, '_Diff_Action_:'
                while Sq_A <= Sq_A_Down:
                    print jsA['behavior']['processes'][0]['calls'][Sq_A]['api']
                    Sq_A = Sq_A + 1
            return

xxxxx=3
with open('./KVM/Win7_Tample/'+str(xxxxx)+'.json',mode='r') as file1: #Win7_CN  Win7_Tample
    with open('./VBOX/Win7_Tample/'+str(xxxxx)+'.json', mode='r') as file2:
        with open('./VM/Win7_Tample/'+str(xxxxx)+'.json',mode='r') as file3:
 #          Cross_Check(file1,'KVM',file2,'VBOX')
         Cross_Check(file1,'KVM',file3,'VMware')
#          Cross_Check(file2,'VBOX',file3,'VMware')