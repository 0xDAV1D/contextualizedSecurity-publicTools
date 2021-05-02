#!/bin/bash

### Author: David Pearson (david@contextualizedsecurity.com)
### Date: 04/29/2021
### This file allows a user to collect passive DNS info from any directory of
### samples they have. It can later be used to supply any names to IP addresses
### that were not identified by passive DNS within the given file and before
### active DNS lookups occur. It will only keep names for IPs that have never
### had a different name associated with it.

wd=$(pwd)
cSecDir="${wd}/contextualizedSecurity"
tmpFile="${cSecDir}/tmp"
csecPDNSFile="${wd}/cSecPassiveDNS.txt"
dirPath=""
f2process=""
dir2process=""
directory=0
oneFile=0
wd=$(pwd)
utilsDir="${wd}/utils"
conversionScriptsDir="${wd}/conversionScripts"

# ############# Argument parsing #############
  if [[ "$#" -eq 0 ]]
  then
    echo "Usage: bash updatePassiveDNSRepository.sh [-f <file to process> | -d <directory to process> ]";
    exit 0
  fi

  while [[ "$#" -gt 0 ]]; do
    case $1 in
        -h) echo "Usage: bash updatePassiveDNSRepository.sh [-f <file to process> | -d <directory to process> ]";
            exit 0
            ;;
        -f) f2process="$2"; shift ;;
        -d) dir2process="$2"; shift ;;
        *) echo "Unknown parameter passed: $1";
           echo "Usage: bash updatePassiveDNSRepository.sh [-f <file to process> | -d <directory to process> ]";
           exit 1 ;;
    esac
    shift
  done

  if [[ $f2process != "" ]]
  then
    if [[ $dir2process != "" ]]
    then
      echo "Usage: bash updatePassiveDNSRepository.sh [-f <file to process> | -d <directory to process> ]";
      exit 0
    elif [[ -z $f2process ]]
    then
      echo "file '$f2process' does not exist."
      exit 0
    fi
    oneFile=1
  elif [[ $dir2process != "" ]]
    then
      if [[ $f2process != "" ]]
      then
        echo "Usage: bash updatePassiveDNSRepository.sh [-f <file to process> | -d <directory to process> ]";
        exit 0
      elif [[ ! -d $dir2process ]]
      then
        echo "directory '$dir2process' does not exist."
        exit 0
      fi
      directory=1
  fi


  if [[ $oneFile == 1 ]]
    then
      fileName=$(basename ${f2process%.*})
      fullName=$f2process
      bash utils/getPassiveDNS.sh $fullName
      rm *_allDNSQueries\.txt
      rm *_allDestinationIPs\.txt
      if [[ -z $csecPDNSFile ]]
      then
        echo "Creating passive DNS file to store all results."
        touch $csecPDNSFile
      fi
      cat $fileName"_passiveDNSNames.txt" >> $csecPDNSFile
      rm $fileName"_passiveDNSNames.txt"
  elif [[ $directory == 1 ]]
    then
      dirPath=$dir2process
      for f in $(ls $dirPath);
      do
        fileName=$(basename ${f%.*})
        fullName=${dirPath}"/"${f}
        #echo "file is " $fileName
        #echo "full file is " $fullName
        bash utils/getPassiveDNS.sh $fullName
        rm *_allDNSQueries\.txt
        rm *_allDestinationIPs\.txt
        if [[ -z $csecPDNSFile ]]
        then
          echo "Creating passive DNS file to store all results."
          touch $csecPDNSFile
        fi
        cat $fileName"_passiveDNSNames.txt" >> $csecPDNSFile
        rm $fileName"_passiveDNSNames.txt"
      done;
  fi

### Sort and keep only the lines that don't have multiple names for the same IP
sort -u $csecPDNSFile > $tmpFile
cat $tmpFile | awk '{print $2, $1}' | uniq -f1 -u | awk '{print $2, $1}' > $csecPDNSFile

### Clean up
rm $tmpFile
