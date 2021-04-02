#!/bin/bash

### Author: David Pearson (david@contextualizedsecurity.com)
### Date: 04/01/2021
### This file leverages tcpdump to filter out all local-to-local and other
### uninteresting traffic. Note that it currently only supports IPv4.
### This file should NOT be called directly.

filePath=$1
fileName=$(basename ${filePath%.*})
reportFile="${fileName}.txt"
filteredFile="${fileName}_filtered.pcapng"
wd=$(pwd)
utilsDir="${wd}/utils"
conversionScriptsDir="${wd}/conversionScripts"

# ############## Remove all of the local/uninteresting traffic ###############
  # Steps:
  # 1.0 Get all of the DNS queries in form <port> <dns.qry.name> <dns.resp.name>
  tcpdump --dont-verify-checksums -vvnr $filePath 'port domain' | grep -E "[1-6][0-9]{0,4}( [A-Za-z]{3,10} | )q:" | awk '{print $3, ($7 ~/^[A-Z]{1,5}\?/ ? $8 : $7), $(NF-1)}' | cut -d"." -f5- | sed s/:// > "${filteredFile}_dnsAll.txt"
  #   (NOTE: above won't work for IPv6 at end because the "." delimiter would be a ":"...TODO!)

  # 1.1 Identify lines from 1.0 that are forward LOCAL lookups
  localForward=$(cat "${filteredFile}_dnsAll.txt" | awk '($3 ~/^(10|127|169\.254|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]|192\.168)\./) {printf "%s or ", $1 }')

  # 1.2 Identify lines from 1.0 that are reverse LOCAL lookups
  localReverse=$(cat "${filteredFile}_dnsAll.txt" | awk '($2 ~/([0-9]{1,3})\.([0-9]{1,3})\.((1[6-9]\.172)|(2[0-9]\.172)|(3[0-1]\.172)|([0-9]{1,3}\.10)|(168\.192))\.in\-addr\.arpa\.$/ ) {printf "%s or ", $1}')

  # 2. Remove LOCAL protocols, including ALL SMB
  localProtocols="445 or 5355 or netbios-ssn or netbios-ns or mdns or ldap or ldaps or bootps or bootpc or 1900"
  # For some reason Ubuntu can't handle llmnr or ssdp by name...
  #localProtocols="445 or llmnr or netbios-ssn or netbios-ns or mdns or ldap or ldaps or bootps or bootpc or ssdp"

  # 3. Confirm at least one IP address is NOT LOCAL (still needs ipv6)
  localToLocalSansDNS="(src net 0.0.0.0/32 or 192.168.0.0/16 or 10.0.0.0/8 or 172.16.0.0/12 or 239.255.255.250/32 or 224.0.0.0/4 or 255.255.255.255/32) and (dst net (0.0.0.0/32 or 192.168.0.0/16 or 10.0.0.0/8 or 172.16.0.0/12 or 239.255.255.250/32 or 224.0.0.0/4 or 255.255.255.255/32)) and not port domain"

  dnsPrefix=" and not (port domain and (src net 10.0.0.0/8 or 192.168.0.0/16 or 172.16.0.0/12) and (dst net 10.0.0.0/8 or 192.168.0.0/16 or 172.16.0.0/12)"
  dnsExpression=""
  if [[ -z $localForward && -z $localReverse ]] #no forward or reverse local lookups
  then
    dnsExpression=""
  else
    if [[ -z $localForward ]]
    then
      dnsExpression="$dnsPrefix and port ($localReverse 0))"
    else
      dnsExpression="$dnsPrefix and port ($localForward 0))"
    fi
  fi
  # Not SMB or any other E-W protocols and not non-DNS local-to-local traffic and not local-to-local DNS traffic with local lookups
  tcpdump -nr $filePath "((not port ($localProtocols)) and not ($localToLocalSansDNS) $dnsExpression and not ip6)" -w "${filteredFile}"

  echo "{\"fileLocation\": \"$filteredFile\"}"
