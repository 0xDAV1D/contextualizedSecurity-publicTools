#!/bin/bash

### Author: David Pearson (david@contextualizedsecurity.com)
### Date: 04/01/2021
#### This file leverages tcpdump to collect all of the DNS queries that were
### seen in the accompanying PCAP file, and then identify the most useful
### domain name associated with them. Note that it currently only supports IPv4
### IP addresses, and that we intentionally don't follow all CNAME values,
### since many point us to less useful CDN/middlebox servers. Finally, please
### note that this file should NOT be called directly.

filePath=$1
fileName=$(basename ${filePath%.*})
tcpDestinationsFile="${fileName}_tcpDestinations.txt"
udpDestinationsFile="${fileName}_udpDestinations.txt"
ipV4DestinationsFile="${fileName}_ipV4Destinations.txt"
destinationsFilePreProcessed="${fileName}_destinationsPre.txt"
destinationsFilePostProcessed="${fileName}_destinationsPost.txt"
passiveDestinationsFilePreProcessed="${fileName}_passiveDestinationsPre.txt"
passiveDestinationsFilePostProcessed="${fileName}_passiveDestinationsPost.txt"
activeLookupsNeeded="${fileName}_activeDestinationsNeeded.txt"
activeLookupsCompleted="${fileName}_activeDestinationsCompleted.txt"
wd=$(pwd)
utilsDir="${wd}/utils"
conversionScriptsDir="${wd}/conversionScripts"

# ############## Set up temporary files ###############
  echo "" > $destinationsFilePreProcessed
  echo "" > $passiveDestinationsFilePreProcessed
  touch $activeLookupsCompleted

# ############# Extract out high-level insights #############
  bash "${utilsDir}/collectInsightsByFilter.sh" "$filePath" "tcp" "$tcpDestinationsFile"
  bash "${utilsDir}/collectInsightsByFilter.sh" "$filePath" "udp" "$udpDestinationsFile"
  bash "${utilsDir}/collectInsightsByFilter.sh" "$filePath" "ip and !(tcp || udp)" "$ipV4DestinationsFile"
  cat $tcpDestinationsFile $udpDestinationsFile $ipV4DestinationsFile > $destinationsFilePreProcessed

# ############## Collect passive hosts #############

  bash "${utilsDir}/collectPassiveDNS.sh" "$filePath" "$passiveDestinationsFilePreProcessed"

# ############## Sort and actively look up destination IPs #############
  cat $passiveDestinationsFilePreProcessed | cut -d" " -f1 | sort -u > $passiveDestinationsFilePostProcessed
  cat $destinationsFilePreProcessed | grep "<->" | tr -s [:space:] | cut -d" " -f3 | cut -d":" -f1 | sort -u > $destinationsFilePostProcessed
  diff -bu $passiveDestinationsFilePostProcessed $destinationsFilePostProcessed | grep -E "^\+[1-9]" | tr -d [=+=] | grep -vE "(^127\.)|(^192\.168\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^239\.255\.255\.250)|(^255\.255\.255\.255)|(^::1$)|(^[fF][cCdD])" > $activeLookupsNeeded
  for line in $(tail +2 $activeLookupsNeeded); do
    res=$(dig +noall +short +tries=1 +retry=0 +time=1 -x $line | head -1 | grep -v ";;" | sed 's/.$//') #only take first record returned, and remove trailing dot
    if [[ $(echo $res | wc -c) -gt 1 ]]
    then
      echo $line " " $res >> $activeLookupsCompleted
    else
      #just write the IP
      echo $line " " $line >> $activeLookupsCompleted
    fi
  done
