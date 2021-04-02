#!/bin/bash

### Author: David Pearson (david@contextualizedsecurity.com)
### Date: 04/01/2021
### This file leverages tcpdump to collect all of the DNS queries that were
### seen in the accompanying PCAP file, and then identify the most useful
### domain name associated with them. Note that it currently only supports IPv4
### IP addresses, and that we intentionally don't follow all CNAME values,
### since many point us to less useful CDN/middlebox servers. Finally, please
### note that this file should NOT be called directly.

filePath=$1
outputFile=$2
fileName=$(basename ${filePath%.*})
allDestinationIPsFile="${fileName}_allDestinationIPs.txt"
allDNSQueriesFile="${fileName}_allDNSQueries.txt"
wd=$(pwd)
utilsDir="${wd}/utils"
conversionScriptsDir="${wd}/conversionScripts"


# ############# Collect all external IPv4 IPs actually used #############
  bash "${utilsDir}/collectInsightsByFilter.sh" "$filePath" "ip" "$allDestinationIPsFile"
  tail +5 $allDestinationIPsFile | awk '{ print ($3 ~ /^(10|127|169\.254|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]|192\.168)\./ ? NR " " "": NR " " $3) }' |sort -k2  | uniq -f1 | sort -nk1,1 | cut -d" " -f2- | cut -d":" -f1 | awk NF > tmpFile
  mv tmpFile $allDestinationIPsFile

# ############# Now collect all DNS queries we've seen ############
  tcpdump --dont-verify-checksums -vvnr $filePath 'port domain' | grep -E "[1-6]{0,1}[0-9]{0,4}( [A-Za-z]{3,10} | )q:" > $allDNSQueriesFile
  grep -Fw -f $allDestinationIPsFile $allDNSQueriesFile | awk 'BEGIN {curPos=0;}
    {
      if ($7 ~/^[A-Z]{1,5}\?/)
      {
        position=8
        name=$8
        records=substr($9,0,index($9, "/")-1)
        computedField=position+(3*records)
      }
      else
      {
        position=7
        name=$7
        records=substr($8,0,index($8, "/")-1)
        computedField=position+(3*records)
      };
      for(curPos=position; curPos <= computedField; curPos += 3)
      {
        nextField=$(curPos+1)
        if ($curPos == "CNAME")
        {
          if (curPos == computedField) #last one
          {
            #print substr(nextField,0,length(nextField)-1), name
          }
          else
          {
            #print substr(nextField,0,length(nextField)-2), name
          }
        }
        else if ($curPos == "A")
        {
          if (curPos == computedField) #last one
          {
            print nextField, name
          }
          else
          {
            print substr(nextField,0,length(nextField)-1), name
          }
        }
        else {} #do nothing in this case
      }
    }
  ' > $outputFile

  backup="${outputFile}.bak"
  cp $outputFile $backup
  cat $backup | sed 's/\.$//' > $outputFile #remove trailing dot for FQDN
  rm $backup
