import os
from datetime import datetime
from pysnmp.hlapi import *
from pysnmp.proto.rfc1905 import VarBind
import platform
import subprocess
import time



def main():
    oid = '.1.3.6.1.4.1.16177.1.200.3.3.0'  #OID
    hostPublic = ''           #Public IP
    hostLocal = ''            #Local IP
    #Debug IP
    #hostPublic = '127.0.0.1'
    #hostLocal = '127.0.0.1'
    bracket = '**************************************************\n'
    response = -1

    

    now = datetime.now()
    timeAndDate = now.strftime("%d/%m %H:%M:%S")

    f = open("log.txt", "a")
    if os.stat("log.txt").st_size != 0:
        f.write('\n')
    f.write(timeAndDate + ' STARTING SCRIPT\nPublic IP: ' + hostPublic + '\nLocal IP: ' + hostLocal + '\nTargetting OID: ' + oid + '\n' + bracket) 
    f.close()
    
    
    while True:

        response = pingPublic(hostPublic)   #Pings hosts public IP

        #Timestamp 
        now = datetime.now()
        timeAndDate = dt_string = now.strftime("%d/%m %H:%M:%S")

        #Reacts on results of ping
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
    parameter = '-n' if platform.system().lower()=='windows' else '-c'

    command = ['ping', parameter, '1', hostPublic]
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
        f.write(string) #if snmp-get fails the log.txt entry will be blank
        f.close()



if __name__ == '__main__':
    main()
