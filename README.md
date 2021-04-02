# contextualizedSecurity-publicTools
The tools found within this repository are public tools available for anyone to use with [Contextualized Security](https://contextualizedsecurity.com/) (however, note that Contextualized Security is currently in an **Alpha** release). At present, the following features are available:

* Conversion tool to go from PCAP/PCAPNG to CSec Flows
* Conversion tool to go from Zeek Flows to CSec Flows

## Dependencies
#### Zeek Conversion Script
Using the Zeek conversion script only requires that you have Zeek conn.log and dns.log files for whatever traffic you're interested in converting. It's that simple! To launch the script, simply type the following:
```
bash prepCSecFlows.sh -z -c someConn.log -d someDNS.log
```

#### PCAP Conversion Script
Using the PCAP conversion script requires that you also have `tcpdump` installed. Other than that, everything that comes with a standard Linux release should suffice. To launch the script, simply type the following:
```
bash prepCSecFlows.sh -p -f somePcapFile.pcap
```

## Samples
Coming soon!

## Questions
If you have any questions about this code, Contextualized Security, or anything else related, feel free to join and ask us on our [Discord server](https://discord.gg/Q6Y4ha2ysX).
