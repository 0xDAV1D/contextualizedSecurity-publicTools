#!/bin/bash

### Author: David Pearson (david@contextualizedsecurity.com)
### Date: 04/01/2021
### This file is the high-level file meant to control collecting passive DNS
### from the incoming file.
### This file should NOT be called directly.

filePath=$1
fileName=$(basename ${filePath%.*})
passiveDNSNames="${fileName}_passiveDNSNames.txt"
wd=$(pwd)
utilsDir="${wd}/utils"
conversionScriptsDir="${wd}/conversionScripts"

  sh "${utilsDir}/collectPassiveDNS.sh" "$filePath" "$passiveDNSNames"
