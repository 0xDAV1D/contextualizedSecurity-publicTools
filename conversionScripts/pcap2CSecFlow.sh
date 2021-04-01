#!/bin/bash

### Author: David Pearson (david@contextualizedsecurity.com)
### Date: 04/01/2021
### This file allows a user to pass in a .cap, .pcap, or .pcapng file and
### return a pre-processed set of destinations. This script should NOT be
### called on its own, but rather should be invoked from prepCSecFlows.sh

filePath=$1
cSecDir=$2
fileName=$(basename ${filePath%.*})
destinationsFilePreProcessed="${fileName}_filtered_destinationsPre.txt"
wd=$(pwd)
tmpFile="${cSecDir}/tmp"
utilsDir="${wd}/utils"
conversionScriptsDir="${wd}/conversionScripts"

# ############## check if file is valid ###############
  status=$(sh "${utilsDir}/checkFileValidity.sh" $filePath)

  if [[ status == "FAIL" ]]
  then
    exit #not valid
  fi

# ############## remove local traffic ###############
  filteredFile=$(sh "${utilsDir}/removeLocalTraffic.sh" $filePath | cut -d"\"" -f4)

# ############## get passive DNS ###############
  sh "${utilsDir}/getPassiveDNS.sh" $filteredFile

# ############## get active DNS ###############
  sh "${utilsDir}/getActiveDNS.sh" $filteredFile

  echo $destinationsFilePreProcessed
