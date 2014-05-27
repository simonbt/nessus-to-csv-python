__author__ = 'simonbeattie'
from xml.dom import minidom
import sys, re

#Parse in the XML file as the main object
xmldoc = minidom.parse('nessus2.xml')

#Open output files
vulnFile = open('vulns.csv','w')
portFile = open('ports.csv','w')

#Write column layers
vulnFile.write('IP, Hostname, Severity, Vulnerability, Port\n')
portFile.write('IP, OS, PORT, Service\n')

#Parse through XML object and grab all elements labeled ReportHost
itemlist = xmldoc.getElementsByTagName('ReportHost')

#Loop through the ReportHost elements
for node in itemlist:
    #Grab out each report Item
    hostItemList = node.getElementsByTagName('ReportItem')
    #Loop through each report item
    for item in hostItemList:
        #Set skip tag to True
        skip = True
        #Parse tag elements
        tags = node.getElementsByTagName('tag')
        #Loop through tag elements
        for i in tags:
            #Grab only tag element that equals host-fqdn
            if i.attributes['name'].value == "host-fqdn":
                #Assign fqdn variable
                fqdn = i.childNodes[0].nodeValue
            #Grab only tag element that equals operating-system
            if i.attributes['name'].value == "operating-system":
                #Assign os variable
                os = i.childNodes[0].nodeValue
        #Set IP Address and HostName
        ip = node.attributes['name'].value
        #Find all Nessus TCP port scans
        if item.attributes['pluginName'].value == "Nessus TCP scanner":
            #If exists, assign ports, and service variable
            ports = item.attributes['protocol'].value + "/" + item.attributes['port'].value
            service = item.attributes['svc_name'].value
            #Write these to file
            portFile.write(ip + ', ' + os + ', ' + ports + ', ' + service + '\n')
            #Write a star
            sys.stdout.write('*')
        #Assign variables for each vulnerability
        sev = item.attributes['severity'].value
        plugin = item.attributes['pluginName'].value
        port = item.attributes['protocol'].value + "/" + item.attributes['port'].value
        #Parse for cvss score
        cvss = item.getElementsByTagName('cvss_base_score')
        for a in cvss:
            try:
                 #Attempt to assign cvss score variable
                 score = a.childNodes[0].nodeValue
                 #If sucess, check if cvss is over 0.0
                 if float(score) > 0.0:
                     #If it is over, then set skip flag to False
                     skip = False
                 #If there is no cvss score then set skip flag to true
            except:
                skip = True
        #If there was no CVSS score, or the score was below 0.1 then continue to the next item
        if skip:
            #Write a dot
            sys.stdout.write('.')
            continue
        #Write an exclamation mark
        sys.stdout.write('!')
        #Write this vulnerability to the output file
        vulnFile.write(ip + ', ' + fqdn + ', ' + sev + ', ' + plugin + ', ' + port + '\n')

print 'Parse Completed!'
#Close open files
vulnFile.close()
