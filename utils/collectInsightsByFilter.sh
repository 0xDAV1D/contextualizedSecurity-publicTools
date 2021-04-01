#!/bin/bash

### Author: David Pearson (david@contextualizedsecurity.com)
### Date: 04/01/2021
### This file leverages tcpdump to collect insights based on the incoming
### filter. It does a bunch of work to figure out which direction is most
### likely the source/destination, since that is highly important for much of
### the higher-level analysis. Please note that this file should NOT be called
### directly.

filePath=$1
filter=$2
outputFile=$3
wd=$(pwd)
utilsDir="${wd}/utils"
conversionScriptsDir="${wd}/conversionScripts"

# ############# Get minTime of file #############
  fileStartTime=$(tcpdump -ttr --dont-verify-checksums -nr $filePath | head -1 | awk '{print $1}')

# ############# Prepare file header #############
  echo "Conversations" >> $outputFile
  echo "Filter: $filter" >> $outputFile
  echo "                                            |       ->      | |       <-      | |    Relative    |   Duration   |" >> $outputFile
  echo "                                            | Frames  Bytes | | Frames  Bytes | |      Start     |              |" >> $outputFile

# ############# Collect destinations #############
  # Use tcpdump to capture directionally-correct src/dst data in one pass
  tcpdump -ttr --dont-verify-checksums -nr $filePath "$filter" | awk -v fileStartTime=$fileStartTime '{
    if ($3 in srcFrames) #we already did initial analysis, so just capture it and move on
    {
      src=$3
      #update srcBytes, srcFrames
      srcFrames[src] += 1
      if ($(NF) ~ /^\([0-9]+\)$/)
      {  srcBytes[src] += substr($NF,2,length($NF)-2)
      }
      else if ($(NF) ~ /^[A-Z]+/)
      { lengthStart=index($0, "length ")
        if (lengthStart > 0)
        { srcBytes[src] += substr($0, lengthStart+7,index(substr($0, lengthStart+7,15),":")-1)
        }
      }
      else
      { srcBytes[src] += $(NF)
      }
      maxTime[src] = $1
    }
    else if (substr($5,0, length($5)-1) in srcFrames) #dest of this row is source, so capture dest data
    {
      src=substr($5,0, length($5)-1) #$3
      dstFrames[src] += 1
      if ($(NF) ~ /^\([0-9]+\)$/)
      {  dstBytes[src] += substr($NF,2,length($NF)-2)
      }
      else if ($(NF) ~ /^[A-Z]+/)
      { lengthStart=index($0, "length ")
        if (lengthStart > 0)
        { dstBytes[src] += substr($0, lengthStart+7,index(substr($0, lengthStart+7,15),":")-1)
        }
      }
      else
      { dstBytes[src] += $(NF)
      }
      maxTime[src] = $1
    }
    else #not yet captured
    {
      if ($3 ~ /^(10|127|169\.254|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]|192\.168)\./) #RFC1918
      {
        split($3,ipArr,".") #capture port
        port=ipArr[5]
        if (port > 49151) #source is local and ephemeral port
        {
          src=$3
          #collect the data
          dst=substr($5,0, length($5)-1)
          dstIpAndPort[src] = dst
          srcFrames[src] = 1
          if ($(NF) ~ /^\([0-9]+\)$/)
          {  srcBytes[src] = substr($NF,2,length($NF)-2)
          }
          else if ($(NF) ~ /^[A-Z]+/)
          { lengthStart=index($0, "length ")
            if (lengthStart > 0)
            { srcBytes[src] = substr($0, lengthStart+7,index(substr($0, lengthStart+7,15),":")-1)
            }
          }
          else
          { srcBytes[src] = $(NF)
          }
          dstFrames[src] = 0
          dstBytes[src] = 0
          minTime[src] = $1
          maxTime[src] = $1
        }
        else #first IP has well-known or registered port, meaning it may actually be dest...
        {
          possibleSrc=substr($5,0, length($5)-1) #figure out if the other side is the source
          if (possibleSrc ~ /^(10|127|169\.254|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]|192\.168)\./) #RFC1918
          {
            split(possibleSrc,ipArr,".") #capture port
            port=ipArr[5]
            if (port > 49151) #possibleSource is local and ephemeral port
            {
              src=possibleSrc
              #collect the data a little differently, since we somehow saw the suspected source as a destination first...
              dst=$3
              dstIpAndPort[src] = dst
              dstFrames[src] = 0
              dstBytes[src] = 0
              minTime[src] = $1
              maxTime[src] = $1
            }
            else #both have ephemeral ports, and we see this packet first. So just call this the source for now
            {
              split($3,ipArr,".")
              otherPort=ipArr[5]
              src=$3
              dst=substr($5,0, length($5)-1)
              dstIpAndPort[src] = dst
              srcFrames[src] = 1
              if ($(NF) ~ /^\([0-9]+\)$/)
              {  srcBytes[src] = substr($NF,2,length($NF)-2)
              }
              else if ($(NF) ~ /^[A-Z]+/)
              { lengthStart=index($0, "length ")
                if (lengthStart > 0)
                { srcBytes[src] = substr($0, lengthStart+7,index(substr($0, lengthStart+7,15),":")-1)
                }
              }
              else
              { srcBytes[src] = $(NF)
              }
              dstFrames[src] = 0
              dstBytes[src] = 0
              minTime[src] = $1
              maxTime[src] = $1
            }
          }
          else #possible source (2nd IP in line) is also not local and may have a well-known or registered port
          {
            split(possibleSrc,ipArr,".") #capture port
            port=ipArr[5]
            if (port > 49151) #possibleSource is NOT local and has ephemeral port
            {
              src=possibleSrc
              #collect the data a little differently, since we somehow saw the suspected source as a destination first...
              dst=$3
              dstIpAndPort[src] = dst
              dstFrames[src] = 0
              dstBytes[src] = 0
              minTime[src] = $1
              maxTime[src] = $1
            }
            else #both have ephemeral ports, and we see this packet first. So just call this the source for now
            {
              split($3,ipArr,".")
              otherPort=ipArr[5]
              src=$3
              dst=substr($5,0, length($5)-1)
              dstIpAndPort[src] = dst
              srcFrames[src] = 1
              #srcBytes[src] = (($(NF) ~ /^\([0-9]+\)$/) ? substr($NF,2,length($NF)-2) : $(NF))
              if ($(NF) ~ /^\([0-9]+\)$/)
              {  srcBytes[src] = substr($NF,2,length($NF)-2)
              }
              else if ($(NF) ~ /^[A-Z]+/)
              { lengthStart=index($0, "length ")
                if (lengthStart > 0)
                { srcBytes[src] = substr($0, lengthStart+7,index(substr($0, lengthStart+7,15),":")-1)
                }
              }
              else
              { srcBytes[src] = $(NF)
              }
              dstFrames[src] = 0
              dstBytes[src] = 0
              minTime[src] = $1
              maxTime[src] = $1
            }
          }
        }
      }
      else #first IP is not a local IP
      {
        possibleSrc=substr($5,0, length($5)-1) #figure out if the other side is the source
        #whether or not the other side is local, the below logic applies
        split(possibleSrc,ipArr,".") #capture port
        port=ipArr[5]
        if (port > 49151) #possibleSource is local and ephemeral port
        {
          src=possibleSrc
          #collect the data a little differently, since we somehow saw the suspected source as a destination first...
          dst=$3
          dstIpAndPort[src] = dst
          dstFrames[src] = 0
          dstBytes[src] = 0
          minTime[src] = $1
          maxTime[src] = $1
        }
        else #both have ephemeral ports, and we see this packet first. So just call this the source for now
        {
          split($3,ipArr,".")
          otherPort=ipArr[5]
          src=$3
          dst=substr($5,0, length($5)-1)
          dstIpAndPort[src] = dst
          srcFrames[src] = 1
          if ($(NF) ~ /^\([0-9]+\)$/)
          {  srcBytes[src] = substr($NF,2,length($NF)-2)
          }
          else if ($(NF) ~ /^[A-Z]+/)
          { lengthStart=index($0, "length ")
            if (lengthStart > 0)
            { srcBytes[src] = substr($0, lengthStart+7,index(substr($0, lengthStart+7,15),":")-1)
            }
          }
          else
          { srcBytes[src] = $(NF)
          }
          dstFrames[src] = 0
          dstBytes[src] = 0
          minTime[src] = $1
          maxTime[src] = $1
        }
      }
    }
  }
  END {for (val in srcFrames) print val, "\t<-> " dstIpAndPort[val], "\t", srcFrames[val], "\t", srcBytes[val], "\t" , dstFrames[val], "\t", dstBytes[val], "\t", (minTime[val]-fileStartTime), "\t", (maxTime[val]-minTime[val])}' >> $outputFile
  backup="${outputFile}.bak"
  cp $outputFile $backup
  cat $backup | sed 's/\./:/4 ; s/\./:/7' > $outputFile #replace IPv4 port dots with colons
  rm $backup
