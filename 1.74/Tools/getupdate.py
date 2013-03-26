#!/usr/bin/python
""" 
Immunity Debugger Updater Lib

(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>} Immunity Debugger Updater Lib


*DONT MESS WITH THIS FILE*

"""

__VERSION__ = '1.0'

import time
import urllib
import sys
import os
import string
import md5
from threading import Thread

class testit(Thread):
   def __init__ (self,file):
      Thread.__init__(self)
      self.file = file
      self.status = -1
   def run(self):
      sys.stdout.write("Updating: %s\n["%self.file)
      while self.status == -1:
         sys.stdout.write("*")
         time.sleep(0.2)
      sys.stdout.write("] - Finished!\n")
         


def doDownload(file):
   filetodownload=file
   URL="https://auth.immunityinc.com/ImmunityDebugger/update/"
   #first we parse the file filename:md5sum
   (file,md5sum)=file.split(":")
   md5sum=md5sum.replace("\n","").replace("\r","")
   #separate dir and file
   (dir,filename)=os.path.split(file)
   #try to make directory in case it didnt existed
   try:
      os.makedirs(dir)
   except OSError, err:
      pass
   try:
      checkf=open(file,"rb")
      md52check=md5.new(checkf.read()).hexdigest()
      checkf.close()
   except:
      md52check="0"
   if  md52check == md5sum:
      print "MD5SUM: %s , skipping file %s" % (md5sum,filename)
   else:
      #download the file
      current = testit(file)
      time.sleep(1)
      current.start()
      urllib.urlretrieve(URL+file,file)
      current.status = 0
      time.sleep(0.5)
   #check md5sum
   checkf=open(file,"rb")
   if md5.new(checkf.read()).hexdigest() == md5sum:
      print "Checking MD5SUM: %s OK!" % md5sum
      checkf.close()
   else: 
      print "MD5SUM FAILED, REDOWNLOADING FILE"
      checkf.close()
      doDownload(file)
   return 
   
def main():
    print "Connecting to Immunity Debugger Update Site..."
    URL="https://auth.immunityinc.com/ImmunityDebugger/update/"
    filelist = urllib.urlopen(URL+"filelist")
    if filelist.readline()[0:8] == '<!DOCTYP':
       print "An Error ocurred while fetching filelist..."
       print "Exiting..."
       time.sleep(2)
       return
    for file in filelist.readlines():
       doDownload(file)
    time.sleep(1)
    print "\nImmunity Debugger Update: FINISHED"
    print "Press ENTER to exit updater..."
    sys.stdin.readline()
    return

if __name__=="__main__":
    main()

