#!/bin/bash

### Author: David Pearson (david@contextualizedsecurity.com)
### Date: 04/01/2021
### This file allows a user to pass in Zeek/Bro conn.log and dns.log files and
### return a pre-processed set of destinations. This script should NOT be
### called on its own, but rather should be invoked from prepCSecFlows.sh

connLog=$1
dnsLog=$2
cSecDir=$3
fileName=$(basename ${connLog%.*})
interimFile="${fileName}_filtered_interim.txt"
allDestinationIPsFile="${fileName}_filtered_allDestinationIPs.txt"
allDNSQueriesFile=$dnsLog
destinationsFilePreProcessed="${fileName}_filtered_destinationsPre.txt"
destinationsFilePostProcessed="${fileName}_filtered_destinationsPost.txt"
passiveDestinationsFilePreProcessed="${fileName}_filtered_passiveDestinationsPre.txt"
passiveDestinationsFilePostProcessed="${fileName}_filtered_passiveDestinationsPost.txt"
activeLookupsNeeded="${fileName}_filtered_activeDestinationsNeeded.txt"
activeLookupsCompleted="${fileName}_filtered_activeDestinationsCompleted.txt"
tmpFile="${cSecDir}/tmp"
tmp2File="${cSecDir}/tmp2"


# ############## Set up temporary files ###############
  touch $activeLookupsCompleted

# ############# Prepare file for expected format and remove local connections #############
  tail +9 $connLog | grep -v ":" | awk '{print $3":"$4 " <-> " $5":"$6 " " $7 " " $8 " " $10 " " $11 " " $17 " " $18 " " $19 " " $20 " " $1 " " $9 " " $16}'| sort -nk12 | tail +2 | grep -viE "<-> ((127\.)|(192\.168\.)|(10\.)|(172\.1[6-9]\.)|(172\.2[0-9]\.)|(172\.3[0-1]\.)|(224\.0\.)|(239\.255\.255\.250)|(255\.255\.255\.255)|(::1)|(ff02:)|(fe80:))" > $tmpFile

# ############# Main conversion from Zeek to CSec Flow #############
  # Capture data as such for each src/dst ip/port 4-tuple:
  #   sPackets = aggregate of all rows in set's $8 field
  #   dPackets = aggregate of all rows in set's $10 field
  #   sBytes = max of all rows in set's $6 field if $5 is NOT "-", $9 if $5 IS "-" (unless just a SYN, then 0)
  #   dBytes = max of all rows in set's $7 field if $5 is NOT "-", $11 if $5 IS "-" (unless just a SYN, then 0)
  echo "" > $tmp2File #clear out the file
  curSPort=0
  absoluteStart=$(head -1 $tmpFile | awk '{print $12}')
  cat $tmpFile | sort -nk1 > $interimFile #now order by timestamp (ascending) by source port

  while IFS= read -r line
  do
    candidateSPort=$(echo $line | cut -d":" -f2 | cut -d" " -f1)
    if [[ "$curSPort" != "$candidateSPort" ]] #Skip when already processed port
    then
      curSPort=$candidateSPort
      cat $interimFile | grep ":$curSPort" | awk -v absoluteStart=$absoluteStart 'function max(m,n) {return m <= n ? n : m} function min(m,n) {return m >= n ? n : m} BEGIN {sPackets=0; dPackets=0; maxNonServiceSB=0; maxNonServiceDB=0; maxServiceSB=0; maxServiceDB=0; chunkStart=9999999999;}
      {
        sPackets+=$8
        dPackets+=$10
        chunkStart=min(chunkStart,$12)
        if ($5 == "-" )
        {
          if ( $14 == "S" )
          {
            maxNonServiceSB=0
            maxNonServiceDB=0
          }
          else if ( maxNonServiceSB == 0 || maxNonServiceDB == 0 )
          {
            maxNonServiceSB=$9
            maxNonServiceDB=$11
          }
          else
          {
            maxNonServiceSB=max(maxNonServiceSB, $9)
            maxNonServiceDB=max(maxNonServiceDB, $11)
          }
        }
        else
        {
          if ( maxServiceSB == 0 || maxServiceDB == 0 )
          {
            maxServiceSB=$6
            maxServiceDB=$7
          }
          else
          {
            maxServiceSB=max(maxServiceSB, $6)
            maxServiceDB=max(maxServiceDB, $7)
          }
        }
      }
      #print srcIP:port <-> dst:port srcPackets srcBytes dstPackets dstBytes relStart duration
      END {print $1, $2, $3, sPackets, max(maxNonServiceSB, maxServiceSB), dPackets, max(maxNonServiceDB, maxServiceDB), (chunkStart-absoluteStart), ($12+$13-chunkStart) }' >> $tmp2File
  fi
  done < "$interimFile"

# ############# Prepare file and update with DNS info #############
  tail +2 $tmp2File > $destinationsFilePreProcessed
  rm $tmpFile $tmp2File

  # Capture all destination IPs from destinationsFilePreProcessed
  cat $destinationsFilePreProcessed | cut -d " " -f3 | cut -d":" -f1 | sort -u | uniq > $allDestinationIPsFile

  # Merge the passive DNS logs from dns.log into file
  # $22 is the string/comma-separated list of answer values
  # TODO: Currently we're only definitely handling A records correctly
  grep -Fw -f $allDestinationIPsFile $allDNSQueriesFile | awk '
    {
      if ($22 ~/,/) #there are multiple records
      {
        name=$10
        numRecords=split($22, records, ",")
        for(i=1; i<=numRecords; i+=1)
        {
          if (records[i] ~/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/)
          {
            print records[i], name
          }
          else {}
        }
      }
      else
      {
        print $22, $10
      }
    }
  ' > $passiveDestinationsFilePreProcessed

  # Sort and actively look up destination IPs
  cat $passiveDestinationsFilePreProcessed | cut -d" " -f1 | sort -u > $passiveDestinationsFilePostProcessed
  cat $allDestinationIPsFile | sort -u > $destinationsFilePostProcessed
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

  echo $destinationsFilePreProcessed
