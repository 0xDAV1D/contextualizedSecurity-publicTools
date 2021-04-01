#!/bin/bash

### Author: David Pearson (david@contextualizedsecurity.com)
### Date: 04/01/2021
### This file determines if the passed in file is of type PCAP or PCAPNG. If so,
### it passes "SUCCESS" to the handling script. If not, it passes "FAIL".
### This script should NOT be called on its own.

filePath=$1
fileName=$(basename ${filePath%.*})
fileType=$(file $filePath)
body="FAIL"

if grepOutput="$(echo $fileType | egrep '(pcap|pcapng) capture')"
  then body="SUCCESS"
  else body="FAIL"
fi
echo $body
