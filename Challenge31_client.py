#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      makkron
#
# Created:     24/08/2015
# Copyright:   (c) makkron 2015
# Licence:     <your licence>
#-------------------------------------------------------------------------------


import urllib.request
import urlparse
import time


def main():
    waiting=0.06
    ret=""
    while true:
        for c in range(0,256):
            #Build parameter request
            data={}
            data["file"]="file"
            data["signature"]=ret+chr(c)
            t1=int(time.time())
            #performing request and retrieving the code
            x = urllib.request.urlopen(url +"?"+urllib.urlencode(data))
            t2=int(time.time())
            code= x.getcode()
            if code == 200:
                return ret
            elif t2-t1 > waiting :
                ret+=chr(c)
                waiting+=0.06
    print(x.read())

if __name__ == '__main__':
    main()
