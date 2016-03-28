#!/usr/bin/python
# @marekq
# www.marek.rocks

from sslyze.server_connectivity import ServerConnectivityInfo, ServerConnectivityError
from sslyze.plugins_process_pool import PluginsProcessPool
from sslyze.plugins_finder import PluginsFinder
import sys, time, hashlib, Queue, threading
from datetime import datetime

q1	= Queue.Queue()
resu	= []

fname	= 'sslaudit.csv'

###

def start():
	if len(sys.argv) > 1:
		inputf  = sys.argv[1]
	else:
		sys.exit('ERROR, invalid input file submitted as argv  -  use ./python scan.py <exampe-input.csv>')

	for x in open(inputf):
		host	= x.strip()
		q1.put(host)

        for x in range(5):
               	t = threading.Thread(target=worker)
	        t.daemon = True
                t.start()
	q1.join()

def worker():
        while not q1.empty():
                get_scan(q1.get())
                q1.task_done()

def get_scan(host):
	try:
		server_info 	= ServerConnectivityInfo(hostname=host, port=443)
	        server_info.test_connectivity_to_server()
		found		= 'True'

	except:
		found		= 'False'

	if found == 'True':
		sslyze_plugins 		= PluginsFinder()
		plugins_process_pool 	= PluginsProcessPool(sslyze_plugins)

		cmds		= ['sslv2', 'sslv3', 'tlsv1', 'tlsv1_1', 'tlsv1_2', 'certinfo_full']
		for x in cmds:
			plugins_process_pool.queue_plugin_task(server_info, x) 

		commonn	= host_match = cert_sha1 = cert_start = extendedval = trusted = cert_end = ouline = isline = puline = cert_alt = cert_unix_start = cert_unix_end = crts = ''
		for x in plugins_process_pool.get_results():
			if x.plugin_command == 'certinfo_full':
				try:
					y		= x.certificate_chain[0].as_dict
					cert_sha1	= str(x.certificate_chain[0].sha1_fingerprint)
					host_match	= str(x.hostname_validation_result)
					extendedval	= str(x.is_leaf_certificate_ev)

					for z in x.path_validation_result_list:
						# check against the MS certificate store using "Microsoft", but you can also use "Mozilla NSS", "Apple" or "Java 6"
						if z.trust_store.name == 'Microsoft': 
							trusted	= str(z.is_certificate_trusted)

				except:
					y				= ''

				if y != '':
					cert_start 		= y['validity']['notBefore']
					cert_end 		= y['validity']['notAfter']
					commonn			= y['subject']['commonName'].lower()

					cert_unix_start		= str(time.mktime(time.strptime(str(cert_start), "%b %d %H:%M:%S %Y %Z"))).split('.')[0]
					cert_unix_end		= str(time.mktime(time.strptime(str(cert_end), "%b %d %H:%M:%S %Y %Z"))).split('.')[0]

					for z in ['organizationName', 'organizationalUnitName', 'localityName', 'stateOrProvinceName', 'countryName']:
						try:
							a	= y['subject'][z]
							ouline	+= str(a)+', '
						except:
							pass

					for z in ['organizationalUnitName', 'organizationName', 'commonName', 'countryName']:
						try:
							a	= y['issuer'][z]
							isline	+= str(a)+', '
						except:
							pass

					for z in ['publicKeyAlgorithm', 'publicKeySize']:
						try:
							a	= y['subjectPublicKeyInfo'][z]
							puline	+= str(a)+', '
						except:
							pass

					try:
						c 		= y['extensions']['X509v3 Subject Alternative Name']['DNS']
						cert_alt	= ', '.join(c)
					except:
						cert_alt	= ''


			elif x.plugin_command != 'certinfo_full':
				if len(x.accepted_cipher_list) != 0:
					crts	+= str(x.plugin_command)+', '

		crts	= crts[:-2]
		puline	= puline[:-2]
		isline	= isline[:-2]
		ouline	= ouline[:-2]

		a	= ''
		b	= [host, commonn, cert_sha1, host_match, extendedval, trusted, cert_start, cert_unix_start, cert_end, cert_unix_end, cert_alt, ouline, isline, puline, crts]
		for c in b:
			a	+= '"'+c+'",'

		resu.append(str(a[:-1]))
		print a[:-1]

def writeres():
	f	= open(fname, 'w')
	f.write('"host","cert-fqdn","cert-sha1","valid-truststore","cert-hostname-match","cert-ev","cert-start","cert-start-unix","cert-end","cert-unix-end","cert-altnames","cert-owner","cert-issuer","cert-sign-type","server-ssl-support"\n')
	for x in resu:
		f.write(x+'\n')
	f.close

	print 'completed cert audit, results at '+fname

start()
writeres()
