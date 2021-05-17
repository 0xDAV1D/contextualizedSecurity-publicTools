#!/bin/bash

### Author: David Pearson (david@contextualizedsecurity.com)
### Date: 04/01/2021
### This file is the main script that should be used to call the other scripts
### in this directory. Call it by either passing in a CAP/PCAP/PCAPNG file:
###
###             bash prepCSecFlows.sh -p -f somePcapFile.pcap
###
### or by passing in the Zeek (Bro) conn.log and dns.log:
###
###             bash prepCSecFlows.sh -z -c someConn.log -d someDNS.log
###
### In either case, all local-to-local traffic will be removed, and the files
### will be converted into a CSec Flow format (which is similar to but more
### lightweight than Zeek flows).

zeek=0
connLog=""
dnsLog=""
pcap=0
pcapFile=""
fileName=""
wd=$(pwd)
utilsDir="${wd}/utils"
conversionScriptsDir="${wd}/conversionScripts"
cSecDir="${wd}/contextualizedSecurity"
csecPDNSFile="${wd}/cSecPassiveDNS.txt"

# ############# Argument parsing #############
  if [[ "$#" -eq 0 ]]
  then
    echo "Usage: bash prepCSecFlows.sh [-z -c <conn.log> -d <dns.log> | -p -f <pcap file>]";
    exit 0
  fi

  while [[ "$#" -gt 0 ]]; do
    case $1 in
        -h) echo "Usage: bash prepCSecFlows.sh [-z -c <conn.log> -d <dns.log> | -p -f <pcap file>]";
            exit 0
            ;;
        -z) zeek=1 ;;
        -p) pcap=1 ;;
        -c) connLog="$2"; shift ;;
        -d) dnsLog="$2"; shift ;;
        -f) pcapFile="$2"; shift ;;
        *) echo "Unknown parameter passed: $1";
           echo "Usage: bash prepCSecFlows.sh [-z -c <conn.log> -d <dns.log> | -p -f <pcap file>]";
           exit 1 ;;
    esac
    shift
  done

  if [[ $pcap == 1 ]]
  then
    if [[ $zeek == 1 ]]
    then
      echo "Usage: bash prepCSecFlows.sh [-z -c <conn.log> -d <dns.log>|-p -f <pcap file>]"
      exit 0
    elif [[ -z $pcapFile ]]
    then
      echo "PCAP file '$pcapFile' does not exist."
      exit 0
    fi
    fileName=$(basename ${pcapFile%.*})
  elif [[ $zeek == 1 ]]
  then
    if [[ $pcap == 1 ]]
    then
      echo "Usage: bash prepCSecFlows.sh [-z -c <conn.log> -d <dns.log>|-p -f <pcap file>]"
      exit 0
    elif [[ -z $connLog ]]
    then
      echo "Zeek connection log '$connLog' does not exist."
      exit 0
    elif [[ -z $dnsLog ]]
    then
      echo "Zeek DNS log '$dnsLog' does not exist."
      exit 0
    fi
    fileName=$(basename ${connLog%.*})
  fi

  if [[ -d $cSecDir ]]
  then
    echo "Storing all output in '$cSecDir'"
  else
    echo "creating directory '$cSecDir' to store all output."
    mkdir $cSecDir
  fi

# ############# Prep vars that needed input from args #############
  tmpFile="${cSecDir}/tmp"
  orderedConnectionsFile="${fileName}_filtered_orderedConnections.txt"
  orderedConnectionsRemainingFile="${fileName}_filtered_orderedConnectionsRemaining"
  passiveDestinationsFilePreProcessed="${fileName}_filtered_passiveDestinationsPre.txt"
  activeLookupsCompleted="${fileName}_filtered_activeDestinationsCompleted.txt"
  cSecJSONFile="${cSecDir}/${fileName}_filtered.json"

# ############# Process the file(s) #############
  if [[ $zeek == 1 ]]
  then
    # Grab the traffic date, and convert from Zeek flows to CSec Flows:
    trafficDate=$(tail +9 $connLog | head -1 | awk '{print $1}')
    destinationsFilePreProcessed=$(bash "${conversionScriptsDir}/zeek2CSecFlow.sh" $connLog $dnsLog $cSecDir)
  elif [[ $pcap == 1 ]]
  then
    # Grab the traffic date, and convert from PCAP data to CSec Flows:
    trafficDate=$(tcpdump -ttr --dont-verify-checksums -nr $pcapFile | head -1 | awk '{print $1}')
    destinationsFilePreProcessed=$(bash "${conversionScriptsDir}/pcap2CSecFlow.sh" $pcapFile $cSecDir)
  fi

  # Raw network flows, before leveraging passive/active DNS
  cat $destinationsFilePreProcessed | grep -E "(<->)" | sort -nk8 > $orderedConnectionsFile

  # Replace any destinations with passive DNS for EXACT session from current
  # file (avoids over-naming samples where IPs have multiple names)
  # This doesn't seem to be working right on OS X...
  IFS=$'\n'
  for line in $(cat $passiveDestinationsFilePreProcessed); do
    ip=$(echo "$line" | awk '{print $1;}')
    dom=$(echo "$line" | awk '{print $2;}')
    sed "s/$ip:/$dom:/1" $orderedConnectionsFile  > $tmpFile && mv $tmpFile $orderedConnectionsFile
  done
  unset IFS

  # Replace any possible destinations with passive DNS from current file that
  # weren't picked up in previous run
  IFS=$'\n'
  for line in $(cat $passiveDestinationsFilePreProcessed); do
    ip=$(echo "$line" | awk '{print $1;}')
    dom=$(echo "$line" | awk '{print $2;}')
    sed "s/$ip:/$dom:/" $orderedConnectionsFile  > $tmpFile && mv $tmpFile $orderedConnectionsFile
  done
  unset IFS

  ### Replace any possible destinations with passive DNS from overall PDNS file,
  ### if it exists. Either way, add current file's DNS to the PDNS file (for
  ### PCAPs).
  if [[ ! -z $csecPDNSFile ]]
  then
    IFS=$'\n'
    for line in $(cat $orderedConnectionsFile); do
      #echo "Line is" $line
      dom=""
      ip=$(echo "$line" | cut -d" " -f3 | cut -d":" -f1)
      if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] #still actually IPv4 IP
      then
        dom=$(grep $ip $csecPDNSFile | cut -d" " -f2 | head -1)
      fi
      if [[ $dom == "" ]] #handle empty case
      then
        dom=$ip
      fi
      sed "s/$ip:/$dom:/" $orderedConnectionsFile  > $tmpFile
      mv $tmpFile $orderedConnectionsFile
    done
    unset IFS
  fi
  if [[ $pcap == 1 ]]
  then
    echo "Adding " $pcapFile "'s DNS lookups to global passive DNS file"
    bash "$utilsDir/updatePassiveDNSRepository.sh" -f $pcapFile
  fi

  # Replace any remaining destinations with active DNS
  IFS=$'\n'
  for line in $(cat $activeLookupsCompleted); do
    ip=$(echo "$line" | awk '{print $1;}')
    dom=$(echo "$line" | awk '{print $2;}')
    sed "s/$ip:/$dom:/" $orderedConnectionsFile  > $tmpFile && mv $tmpFile $orderedConnectionsFile
  done
  unset IFS

# ############# Prepare file for final format #############
  cat $orderedConnectionsFile | grep -viE "<-> ((127\.)|(192\.168\.)|(10\.)|(172\.1[6-9]\.)|(172\.2[0-9]\.)|(172\.3[0-1]\.)|(224\.0\.)|(239\.255\.255\.250)|(255\.255\.255\.255)|(::1)|(ff02:)|(fe80:))" >> $tmpFile && mv $tmpFile $orderedConnectionsFile

  # Hash the file
  hash=$(shasum $orderedConnectionsFile | awk '{print $1}')

  # Turn file into JSON format
  csecFlows=$(cat $orderedConnectionsFile | tr -s '[:blank:]' ' ' | awk '{print "\"src\":",$1"\"", "\"dst\":", "\""$3"\"", "\"srcPkts\":", $4, "\"srcBytes\":", $5, "\"dstPkts\":", $6, "\"dstBytes\":", $7, "\"relativeStart\":", $8, "\"duration\":", $9}' | sed -e 's/: /:/g; s/ /,/g ; s/^"src":/{&"/ ; s/,dst:/"&"/; s/,srcPkts:/"&/; s/[0-9]$/&},/')
  csecFlows=$(echo "["$csecFlows | sed 's/,$//')"]"

  if [[ "$(echo $csecFlows | wc -c)" -le 2 ]]
  then
    csecFlows="[]"
  fi

  # Write CSec flows to a file for upload
  echo "{\"hash\":\"$hash\",\"trafficDate\":\"$trafficDate\",\"fileName\":\"$fileName\",\"csecFlows\":"$csecFlows"}" > $cSecJSONFile
  echo "file at" $cSecJSONFile "is ready for upload to Contextualized Security!"

  # Clean up unneeded files
  rm "${fileName}_filtered"*.txt

  if [[ $pcap == 1 ]]
  then
    rm "${fileName}_filtered"*.pcap*
  fi
