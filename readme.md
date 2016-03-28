ssl-audit
=========

A very fast network scanner of SSL server configurations 

Description
------------

The SSL auditor can be used to scan large amounts of DNS names in paralel for common SSL weaknesses, such as usage of deprecated SSLv2/SSLv3 certificates, self signed certificates and improper usage of wildcards certificates for your domains. The results are shown in the console but also stored in a CSV for easy tracking of certificates over time. The tool leverages the existing "sslyze" library but allows a handier CSV export and it will run quicker due to multiprocessing. 

Installation
------------

The tool has been tested on Debian and Mac OSX, but should work on other platforms too. Besides Python, install the following two packages using 'python-pip';

	$ pip install sslyze 
	$ pip install nassl

You can run 'python sslaudit.py example-input.csv' to check if the tool works well on your machine.  The 'ssl-audit-example-output.csv' file contains an example of a CSV report the tool should create when it runs succesfully. 

Depending on the specs of your machine and the scope you want to scan, consider to change the amount of threads used by the tool. The default "sslyze" timeouts and retry counts are being used, which could lead to very slow performance on some networks. 

Usage
-----

The tool needs a list of DNS names or IP addresses to scan;

	$ python ssl-audit.py example.csv

Results of the scan are shown on screen and stored in "sslaudit.csv" in the current directory. If you manage a large amount of servers, you could consider to run the job as a cron with an input file containing your domain and to create alerts whenever certificates will expire or to quickly have an overview of SSL servers when yet another OpenSSL exploit becomes public knowledge...

Contact
-------

For any questions or fixes, please reach out to @marekq!
