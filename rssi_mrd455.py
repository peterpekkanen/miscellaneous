import os
from datetime import datetime
from pysnmp.hlapi import *
from pysnmp.proto.rfc1905 import VarBind
import platform
import subprocess
import time



def main():
    oid = '.1.3.6.1.4.1.16177.1.200.3.3.0'  #OID
    hostPublic = '217.174.88.24'           #Public IP
    hostLocal = '192.168.2.200'            #Local IP
    #Debug IP
    #hostPublic = '127.0.0.1'
    #hostLocal = '127.0.0.1'
    bracket = '**************************************************\n'
    response = -1   #Dummy

    

    now = datetime.now()
    timeAndDate = now.strftime("%d/%m %H:%M:%S")

    f = open("log.txt", "a")
    if os.stat("log.txt").st_size != 0: #File formating
        f.write('\n')
    f.write(timeAndDate + ' STARTING SCRIPT\nPublic IP: ' + hostPublic + '\nLocal IP: ' + hostLocal + '\nTargetting OID: ' + oid + '\n' + bracket) 
    f.close()
    
    
    while True:

        response = pingPublic(hostPublic)   #Pings public ip

        #Time
        now = datetime.now()
        timeAndDate = now.strftime("%d/%m %H:%M:%S")

        #Result of pings
        if response == 0:
            print(bracket)
            logThis = timeAndDate + " PINGS SUCCESSFUL "
            print(logThis)
            f = open("log.txt", "a")
            f.write('\n')
            f.write(logThis + ' - ')
            f.close()
            getSnmp(oid, hostLocal)
            print(bracket)


        elif response == 1:
            print(bracket)
            logThis = timeAndDate + " PINGS FAILED "
            print(logThis)
            f = open("log.txt", "a")
            f.write('\n')
            f.write(logThis + ' - ')
            f.close()
            getSnmp(oid, hostLocal)
            print(bracket)
        else:
            print("ERROR\n")

        time.sleep(2)
        
def pingPublic(hostPublic):
    i = '1' #Number of pings
    parameter = '-n' if platform.system().lower()=='windows' else '-c'

    command = ['ping', parameter, i, hostPublic]
    response = subprocess.call(command)

    return response

def getSnmp(oid, host):

    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(SnmpEngine(),
               CommunityData('public', mpModel=0),
               UdpTransportTarget((host, 161)),
               ContextData(),
               ObjectType(ObjectIdentity(oid)))
    )
    if errorIndication:
        print(errorIndication)
    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))


    for varBind in varBinds:
        string = str(varBind)
        print(' = '.join([x.prettyPrint() for x in varBind]))
        f = open("log.txt", "a")
        dbmVal = rssiDbm(int(string[-2:]))
        f.write(string + " ; dBm = " + str(dbmVal)) #If blank statement snmp-get failed.
        f.close()

def rssiDbm(value): #Converting RSSI to dBm (Inaccurate)
    if value <= 4:
        return -100
    elif value <= 8:
        return -90
    elif value <= 14:
        return -80
    elif value <= 20:
        return -70
    elif value <= 26:
        return -60
    elif value > 26:
        return -50
    else:
        print("ERROR")


if __name__ == '__main__':
    main()
