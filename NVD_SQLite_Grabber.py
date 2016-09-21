#!/usr/bin/python

import urllib2
import zipfile
import sqlite3
import xml.etree.ElementTree
import gzip
import os
import datetime
import time
import re
from lxml import etree
from termcolor import colored
from mechanize import *

VERSION="0.1"
DLPAGE="https://nvd.nist.gov/download.cfm"

def printBanner():
	print colored("Starting NVD SQLite Grabber...","blue","on_white")

def download_xml_data (file):

        	url = file
        	file_name = url.split('/')[-1]
        	u = urllib2.urlopen(url)
        	f = open(file_name, 'wb')
        	meta = u.info()
        	file_size = int(meta.getheaders("Content-Length")[0])
        	print " Downloading: %s Bytes: %s" % (file_name, file_size)

        	file_size_dl = 0
        	block_sz = 8192
        	while True:
                	buffer = u.read(block_sz)
                	if not buffer:
                        	break
                	file_size_dl += len(buffer)
                	f.write(buffer)
                	status = r"%10d [%3.2f%%]" % (file_size_dl, file_size_dl * 100. / file_size)
			status = status + chr(8)*(len(status)+1)
                	print status,
        	f.close()
		return file_name

def initDatabase(dbname):
	if (not os.path.isfile(dbname)):
		print "Database file does not exists. Initializing it"
	
	conn = sqlite3.connect(dbname)
    	c = conn.cursor()
	
	c.execute('''CREATE TABLE IF NOT EXISTS download_dates (
	dldate_id INTEGER PRIMARY KEY AUTOINCREMENT, 
	download_link TEXT, 
	feed_year TEXT,
	feed_size REAL,
	last_download INTEGER)''')

	c.execute('''create table if not exists vulnerability (
	vuln_id integer primary key autoincrement,
        cve_id text unique,
        cvss_score real,
        access_vector text,
        access_complexity text,
        authentication text,
        confidentiality_impact text,
        integrity_impact text,
        availability_impact text,
        description text,
	cwe test,
	published int,
	modified int,
	dldate_id int,
	FOREIGN KEY(dldate_id) REFERENCES download_dates(dldate_id))''')
	
	c.execute('''create table if not exists cpe (
	cpe_id integer primary key autoincrement,
        cpe text,
	part text,
	vendor text,
	product text,
	version text,
	update_date text,
	edition text,
	language text)''')
	
	c.execute('''create table if not exists cpe_to_cve (
        cpe_id text,
        vulnerability_id text,
	FOREIGN KEY (cpe_id) REFERENCES cpe(cpe_id),
	FOREIGN KEY (vulnerability_id) REFERENCES vulnerability(vuln_id))''')

	c.execute('''CREATE INDEX IF NOT EXISTS vulncve_idx ON vulnerability(cve_id)''')

	c.execute('''CREATE TABLE IF NOT EXISTS software (
	software_id integer primary key autoincrement,
	vendor text,
	product text,
	version text)''')

	c.execute('''CREATE TABLE IF NOT EXISTS scanresult (
	result_id integer primary key autoincrement,
	software_id int,
	vuln_id,
	FOREIGN KEY (software_id) REFERENCES software(software_id),
	FOREIGN KEY (vuln_id) REFERENCES vulnerability(vuln_id))''')
	
	return conn

def closeDatabase(conn):
	conn.close()

def storeDownloadDate(conn,dllink,feed_year,feed_size):
	dlepoch = int(time.time())
	cur = conn.cursor()
	res = cur.execute('''INSERT INTO download_dates(download_link,feed_year,feed_size,last_download) VALUES(?,?,?,?)''',(dllink,feed_year,feed_size,dlepoch))
	pk=cur.lastrowid
	conn.commit()
	return pk

def storeCPE (conn,cpe):
	part=vendor=product=version=update=edition=language = '?'
	cpesplit=cpe.split(":")
	if len(cpesplit)>1 and cpesplit[1] is not None:
        	part=cpesplit[1]
    	if len(cpesplit)>2 and cpesplit[2] is not None:
        	vendor=cpesplit[2]
    	if len(cpesplit)>3 and cpesplit[3] is not None:
        	product=cpesplit[3]
    	if len(cpesplit)>4 and cpesplit[4] is not None:
        	version=cpesplit[4]
    	if len(cpesplit)>5 and cpesplit[5] is not None:
        	update=cpesplit[5]
    	if len(cpesplit)>6 and cpesplit[6] is not None:
        	edition=cpesplit[6]
    	if len(cpesplit)>7 and cpesplit[7] is not None:
		language=cpesplit[7]
	cur = conn.cursor()
	res = cur.execute('''INSERT INTO cpe(cpe,part,vendor,product,version,update_date,edition,language) VALUES(?,?,?,?,?,?,?,?)''',(cpe,part,vendor,product,version,update,edition,language))
	pk=cur.lastrowid
	conn.commit()
	return pk

def searchCPE (conn, cpe_text):
	cpe = None
	cur = conn.cursor()
	res = cur.execute('''SELECT cpe FROM cpe WHERE cpe = ? LIMIT 1''',(cpe_text,))
	results = res.fetchall()
	if len(results) > 0:
		cpe = results[0][0]
	return cpe

def storeCPEtoCVE(vulnid,cpeid):
    cur = conn.cursor()
    res = cur.execute('''INSERT INTO cpe_to_cve(cpe_id,vulnerability_id) VALUES(?,?)''',(cpeid,vulnid))
    conn.commit()


def storeVuln(cve_id, cvss_score,access_vector,access_complexity, authentication, confidentiality_impact, integrity_impact, availability_impact, description, cwe, published, modified, cpetextlist):
	cpeid = None
	vulid = None
	cur = conn.cursor()
	published_date=published.split(".")[0]
	modified_date=modified.split(".")[0]
	pubepoch=int(time.mktime((time.strptime(published_date,"%Y-%m-%dT%H:%M:%S"))))
	modepoch=int(time.mktime((time.strptime(modified_date,"%Y-%m-%dT%H:%M:%S"))))
	res = cur.execute('''INSERT INTO vulnerability(cve_id,cvss_score,access_vector,access_complexity, authentication, confidentiality_impact, integrity_impact, availability_impact, description, cwe, published, modified) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''',(cve_id,cvss_score,access_vector,access_complexity, authentication, confidentiality_impact, integrity_impact, availability_impact, description, cwe, pubepoch, modepoch))
	vulid = cur.lastrowid
	conn.commit()
	for cpetext in cpetextlist:
		cpeid = searchCPE(conn,cpetext)
		if cpeid is None:
			cpeid = storeCPE(conn,cpetext)
            
		storeCPEtoCVE(vulid,cpeid)

def hasToBeUpdated(conn,dllink,updatedepoch):
	lastdownload = 0
	cur = conn.cursor()
	res = cur.execute('''SELECT last_download FROM download_dates WHERE download_link = ? LIMIT 1''',(dllink,))
	results = res.fetchall()
	if len(results) > 0:
		lastdownload = results[0][0]
    	# compare the last time we updated this link with the updated date shown in the web page 
	return lastdownload < updatedepoch

def isVulnInDatabase(conn,cveid):
	cur = conn.cursor()
	res = cur.execute('''SELECT vuln_id FROM vulnerability WHERE cve_id = ? LIMIT 1''',(cveid,))
	results = res.fetchall()
	return len(results) > 0

def wasVulnUpdated(conn,cveid,modified):
	modified_date = 0
	cur = conn.cursor()
	modified=modified.split(".")[0]
	modepoch=int(time.mktime((time.strptime(modified,"%Y-%m-%dT%H:%M:%S"))))
	res = cur.execute('''SELECT modified FROM vulnerability WHERE cve_id = ? LIMIT 1''',(cveid,))
	results = res.fetchall()
	if len(results) > 0:
		modified_date = results[0][0]
	return modepoch > modified_date

def updateVuln(conn,cve_id,cvss_score,access_vector,access_complexity, authentication, confidentiality_impact, integrity_impact, availability_impact, description, cwe, published, modified,cpetextlist):
	cpeid = None
	vuln_id = None
	cur = conn.cursor()
	# datesformat: "2015-05-11T21:59:13.853-04:00"
	published_date=published.split(".")[0]
	modified_date=modified.split(".")[0]
	pubepoch=int(time.mktime((time.strptime(published_date,"%Y-%m-%dT%H:%M:%S"))))
	modepoch=int(time.mktime((time.strptime(modified_date,"%Y-%m-%dT%H:%M:%S"))))
    
	res = cur.execute('''SELECT vuln_id FROM vulnerability WHERE cve_id = ? LIMIT 1''',(cve_id,))
	results = res.fetchall()
	if len(results) > 0:
 		vuln_id = results[0][0]
    
	# Delete the previous affected CPEs and insert the new ones
	res = cur.execute('''DELETE FROM cpe_to_cve WHERE vulnerability_id=?''',(vuln_id,))
    
	res = cur.execute('''UPDATE vulnerability
	SET cve_id=?,cvss_score=?,access_vector=?,access_complexity=?,authentication=?,confidentiality_impact=?,integrity_impact=?,availability_impact=?,description=?,cwe=?,published=?,modified=?
WHERE vuln_id=?''',(cve_id,cvss_score,access_vector,access_complexity, authentication, confidentiality_impact, integrity_impact, availability_impact, description, cwe, pubepoch, modepoch,vuln_id))
	vulnpk=cur.lastrowid
	conn.commit()
    
	# save the cpe list
	for cpetext in cpetextlist:
		cpeid = searchCPE(conn,cpetext)
		if cpeid is None:
			cpeid = storeCPE(conn,cpetext)
            
		storeCPEtoCVE(vuln_id,cpeid)

	return vuln_id

##################
###### MAIN ######
##################

br = Browser() #
printBanner()

conn = initDatabase("vulnerabilityscan.sqlite3")

br.open(DLPAGE) #
body=br.response().read() #

html=etree.HTML(body)#

feedtable = html.xpath("//table[@class='xml-feed-table']")[0]#

nrow=1#
row=0#
for trow in feedtable.xpath("tbody/tr"):#

	#17 for 2016 if 2017 then change to 18
	if row == 17:#
		break;#

	feed = updated = dllink = size = ""#

	regexp_feed = r'<tr class=\'xml-feed-desc-row\'>\s+<td rowspan=\'3\'>(.*)<\/td><'#
	pattern = re.compile(regexp_feed)#
	feeds = re.findall(pattern, body)#
	feed = feeds[row]#
	#print feed#

	regexp_updated = r'<tr class=\'xml-feed-desc-row\'>\s+<td rowspan=\'3\'>.*<\/td><td rowspan=\'3\'>(.*)<br\/>'#
	pattern = re.compile(regexp_updated)#
	updated = re.findall(pattern, body)#
	updatedepoch = int(time.mktime((time.strptime(updated[row],"%m/%d/%Y"))))#
	#print updatedepoch#

	regexp_dllink = r'<td class=\'xml-file-type file-20\'><a href=\'(https:\/\/static\.nvd\.nist\.gov\/feeds\/xml\/cve\/nvdcve-2\.0-.*\.xml.gz)\' target=\'_blank\'>G'#
	pattern = re.compile(regexp_dllink)#
	dllinks = re.findall(pattern, body)#
	dllink = dllinks[row]#
	#print dllink#

	regexp_size = r'xml.gz\' target=\'_blank\'>https<\/a>\)<\/td>\s+<td class=\'xml-file-size file-20\'>([0-9]+.[0-9]+)<\/td>'#
	pattern = re.compile(regexp_size)#
	sizes = re.findall(pattern, body)#
	size = float(sizes[row])#
	#print size#
    
	row+=1#
	nrow+=3#

	if hasToBeUpdated(conn,dllink,updatedepoch):#

		url = dllink
		file_name = download_xml_data(url)
		dlname = dllink.split('/')[-1]
		# Unzip and parse the file to store it in sqlite3
		g = gzip.open(file_name,"rb")
		gcontent = g.read()
		g.close() # Free memory
		g = None
		print "Now, importing content of the file %s" % dlname
		ifxml = etree.XML(gcontent)
		gcontent = None # Free memory

		for entry in ifxml.getchildren():
			cve_id = access_vector = access_complexity = authentication = confidentiality_impact = integrity_impact = availability_impact = description = cwe = ""
			cvss_score = 0.0
			cpetextlist = []
			modified = published = ""

			cveide = entry.find("{http://scap.nist.gov/schema/vulnerability/0.4}cve-id")
			if cveide is not None:
				cve_id = cveide.text
			cwee = entry.find("{http://scap.nist.gov/schema/vulnerability/0.4}cwe")
			if cwee is not None:
				cwe = cwee.values()[0]

			cvsseleme =entry.find("{http://scap.nist.gov/schema/vulnerability/0.4}cvss") 
			if cvsseleme is not None:
				cvsselem = cvsseleme.getchildren()[0]
				cvss_score = float(cvsselem.find("{http://scap.nist.gov/schema/cvss-v2/0.2}score").text)
				access_vector = cvsselem.find("{http://scap.nist.gov/schema/cvss-v2/0.2}access-vector").text
				access_complexity = cvsselem.find("{http://scap.nist.gov/schema/cvss-v2/0.2}access-complexity").text
				authentication = cvsselem.find("{http://scap.nist.gov/schema/cvss-v2/0.2}authentication").text
				confidentiality_impact = cvsselem.find("{http://scap.nist.gov/schema/cvss-v2/0.2}confidentiality-impact").text
				integrity_impact = cvsselem.find("{http://scap.nist.gov/schema/cvss-v2/0.2}integrity-impact").text
				availability_impact = cvsselem.find("{http://scap.nist.gov/schema/cvss-v2/0.2}availability-impact").text
	
			modifiede = entry.find("{http://scap.nist.gov/schema/vulnerability/0.4}last-modified-datetime")
			if modifiede is not None:
				modified = modifiede.text
     	               
			publishede = entry.find("{http://scap.nist.gov/schema/vulnerability/0.4}published-datetime")
			if publishede is not None:
				published = publishede.text

			summarye = entry.find("{http://scap.nist.gov/schema/vulnerability/0.4}summary")
			if summarye is not None:
				description = summarye.text
	
			cpeliste = entry.find("{http://scap.nist.gov/schema/vulnerability/0.4}vulnerable-software-list")
			if cpeliste is not None:
				for cpee in cpeliste.getchildren():
					cpetextlist.append(cpee.text)

		#print colored(" =================","cyan")
			print colored("Import %s into the database" % cve_id,"cyan") 
		#print colored(" =================","cyan")
		#print " * cvss_score: %s" % cvss_score
		#print " * access_vector: %s" % access_vector
		#print " * access_complexity: %s" % access_complexity
		#print " * authentication: %s" % authentication
		#print " * confidentiality_impact: %s" % confidentiality_impact
		#print " * integrity_impact: %s" % integrity_impact
		#print " * availability_impact: %s" % availability_impact
		#print " * N of cpe: %s" % len(cpetextlist)

			if (not isVulnInDatabase(conn, cve_id)):
				storeVuln(cve_id,cvss_score,access_vector,access_complexity, authentication, confidentiality_impact, integrity_impact, availability_impact, description, cwe, published, modified, cpetextlist)
			else:
				if (wasVulnUpdated(conn,cve_id,modified)):
					print colored("Vulnerability %s has been updated. Updating in database" % cve_id,"yellow")
					updateVuln(conn,cve_id,cvss_score,access_vector,access_complexity, authentication, confidentiality_impact, integrity_impact, availability_impact, description, cwe, published, modified,cpetextlist)
				else:
					print colored("Vulnerability %s is already in the database" % cve_id,"red")

		if os.path.isfile('./' + file_name):
			print 'Delete downloaded file ' + file_name
			os.remove('./' + file_name)
		storeDownloadDate(conn,dllink,feed,size)#			

	else:#
        	print colored("File %s is up to date. Not downloading." % dllink,"green")#


closeDatabase(conn)#
