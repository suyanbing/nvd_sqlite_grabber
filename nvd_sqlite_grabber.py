import sqlite3
import requests
from lxml import html
import time, random
from termcolor import colored
import urllib2
import gzip
import re
import dateutil.parser
from datetime import datetime
from lxml import etree
import progressbar
import os

dllist = ['https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Modified.xml.gz',\
				'https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Recent.xml.gz',\
				'https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2002.xml.gz',\
				'https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2003.xml.gz',\
				'https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2004.xml.gz',\
				'https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2005.xml.gz',\
				'https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2006.xml.gz',\
				'https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2007.xml.gz',\
				'https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2008.xml.gz',\
				'https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2009.xml.gz',\
				'https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2010.xml.gz',\
				'https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2011.xml.gz',\
				'https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2012.xml.gz',\
				'https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2013.xml.gz',\
				'https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2014.xml.gz',\
				'https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2015.xml.gz',\
				'https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2016.xml.gz',\
				'https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2017.xml.gz']

metalist = ['https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-Modified.meta',\
				'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-Recent.meta',\
				'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2002.meta',\
				'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2003.meta',\
				'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2004.meta',\
				'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2005.meta',\
				'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2006.meta',\
				'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2007.meta',\
				'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2008.meta',\
				'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2009.meta',\
				'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2010.meta',\
				'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2011.meta',\
				'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2012.meta',\
				'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2013.meta',\
				'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2014.meta',\
				'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2015.meta',\
				'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2016.meta',\
				'https://static.nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-2017.meta',]

def download_xml_data (file):

        	url = file
        	file_name = url.split('/')[-1]
        	u = urllib2.urlopen(url)
        	f = open(file_name, 'wb')
        	meta = u.info()
        	file_size = int(meta.getheaders("Content-Length")[0])
        	print str(datetime.now()).split('.')[0] + "\t" + " Downloading: %s Bytes: %s" % (file_name, file_size)

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

def update_cve_db():
	for idx, metadata in enumerate(metalist):
		r = requests.get(metadata)
		regex_last_mod = re.compile(r'lastModifiedDate:(.*)')
		updated = regex_last_mod.findall(r.text)
		updated = updated[0].strip('\t\r\n')
		datetime = dateutil.parser.parse(updated)
		updatedepoch = int(time.mktime(datetime.timetuple()))
		feed_tmp = dllist[idx].split('.xml.gz')[0]
		feed = feed_tmp.split('https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-')[-1]
		dllink = dllist[idx]
		results = c.execute('''SELECT last_download FROM download_dates WHERE link = ?''',(dllink,))
		result = results.fetchall()
		if result:
			last_download = int(result[0][0])
			if last_download < updatedepoch:
				import_download_date(dllink,updatedepoch)
				import_cves(dllink)
			else:
				print str(datetime.now()).split('.')[0] + "Already up-to-date."
		else:
			import_download_date(dllink,updatedepoch)
			import_cves(dllink)

def import_download_date(link,last_download):
		results = c.execute('''SELECT last_download FROM download_dates WHERE link = ?''',(link,))
		result = results.fetchall()
		if not result:
			c.execute('''INSERT INTO download_dates(link,last_download) VALUES (?,?)''',(link,last_download))
		else:
			c.execute('''UPDATE download_dates SET last_download = ? WHERE link = ?''', (last_download,link))

def import_cves(dllink):

	url = dllink
	file_name = download_xml_data(url)
	dlname = dllink.split('/')[-1]
	# Unzip and parse the file to store it in sqlite3
	g = gzip.open(file_name,"rb")
	gcontent = g.read()
	g.close() # Free memory
	g = None
	print str(datetime.now()).split('.')[0] + "\t" + "Now, importing content of the file %s" % dlname
	ifxml = etree.XML(gcontent)
	gcontent = None # Free memory
	bar = progressbar.ProgressBar(maxval=len(ifxml.getchildren()), \
	    widgets=[progressbar.Bar('#', '[', ']'), ' ', progressbar.Percentage()])
	bar.start()
	i = 0
	for entry in ifxml.getchildren():
				cve_id = access_vector = access_complexity = authentication = confidentiality_impact = integrity_impact = availability_impact = description = cwe = ""
				cvss_score = 0.0
				cpetextlist = []
				modified = published = ""

				cveide = entry.find("{http://scap.nist.gov/schema/vulnerability/0.4}cve-id")
				if cveide is not None:
					cve_id = cveide.text
				#cwee = entry.find("{http://scap.nist.gov/schema/vulnerability/0.4}cwe")
				#if cwee is not None:
				#	cwe = cwee.values()[0]
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
					#print modified
    	               
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
				published_date=published.split(".")[0]
				modified_date=modified.split(".")[0]
				pubepoch=int(time.mktime((time.strptime(published_date,"%Y-%m-%dT%H:%M:%S"))))
				modepoch=int(time.mktime((time.strptime(modified_date,"%Y-%m-%dT%H:%M:%S"))))
	
				results = c.execute('''SELECT modified FROM cves WHERE cveid = ?''',(cve_id,))
				result = results.fetchall()
				if result:
					if modified > int(result[0][0]):
						#print 'Updating %s' % (cve_id)
						c.execute('''UPDATE cves SET cvss = ?, access_vector = ?, access_complexity = ?,
									authentication = ?, confidentiality_impact = ?,
									integrity_impact = ?, availability_impact = ?,
									description = ?, published = ?, modified = ? WHERE cveid = ?''',(cvss_score,access_vector,access_complexity,authentication,confidentiality_impact,integrity_impact,availability_impact,description,pubepoch,modepoch,cve_id))
						for cpe in cpetextlist:
							c.execute('''DELETE FROM cpe_cve WHERE cveid = ?''',(cve_id,))
							c.execute('''INSERT INTO cpe_cve (cpe,cveid) VALUES (?,?)''',(cpe,cve_id))
					#else:
						#print '%s is up-to-date.' % (cve_id)
				else:
					#print 'Importing %s' % (cve_id)
					c.execute('''INSERT INTO cves (cvss,access_vector,access_complexity,authentication,confidentiality_impact,integrity_impact,availability_impact,description,published,modified,cveid) VALUES (?,?,?,?,?,?,?,?,?,?,?)''',(cvss_score,access_vector,access_complexity,authentication,confidentiality_impact,integrity_impact,availability_impact,description,pubepoch,modepoch,cve_id))
					for cpe in cpetextlist:
						c.execute('''INSERT INTO cpe_cve (cpe,cveid) VALUES (?,?)''',(cpe,cve_id))
				bar.update(i+1)
				i += 1
	bar.finish()
	conn.commit()
	if os.path.isfile('./' + file_name):
		#print str(datetime.now()).split('.')[0] + "\t" + 'Delete downloaded file ' + file_name
		os.remove('./' + file_name)

conn = sqlite3.connect('vul.db')
c = conn.cursor()

c.execute('''CREATE TABLE IF NOT EXISTS cves (
		cveid STRING,
		cvss FLOAT,
		access_vector STRING,
		access_complexity STRING,
		authentication STRING,
		confidentiality_impact STRING,
		integrity_impact STRING,
		availability_impact STRING,
		description STRING,
		published INTEGER,
		modified INTEGER,
		vuldb STRING,
		PRIMARY KEY (cveid))''')

c.execute('''CREATE TABLE IF NOT EXISTS download_dates(
		link STRING,
		last_download INTEGER,
		PRIMARY KEY (link))''')

c.execute('''CREATE TABLE IF NOT EXISTS cpe_cve(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		cpe STRING,
		cveid STRING,
		FOREIGN KEY (cveid) REFERENCES cves(cveid))''')

update_cve_db()
