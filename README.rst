auditd-python-parser
========

An in development python library to parse raw auditd events generated on a linux system. This is done only using the audit.log* files and doesn't require the use of ausearch or similar. The logs can also be parsed on a Windows system.

The library tries to keep to the key fields for each event type and generates additional fields to enable process ancestry (process GUIDs) and event linkage similar to how SysmonForLinux does. Some events are enriched where possible such as the network events by adding the process commandline to the network connection where possible.

Install the package using PIP "pip install auditd-python-parser" and then import auditdpythonparser. The package exposes one funcion that you can call - parsedata(data). Currently it returns process, network, filecreate & file open.

.. code:: python

    import auditdpythonparser 
    f = open("audit.log", "r")
    rawdata = f.read()
    f.close()   
    results = auditdpythonparser.parsedata(rawdata)

    dfprocessevents = results["process"]
    dfnetworkevents = results["network"]
    dffilecreateevents = results["filecreate"]
	dffileopenatevents = results["fileopenat"]
	dfuserauthevents = results["userauth"]
    
Process Event Example Output
--------------
.. image:: https://github.com/exeronn/auditd-python-parser/raw/main/images/processevents.PNG 
Network Event Example Output
--------------
.. image:: https://github.com/exeronn/auditd-python-parser/raw/main/images/networkevents.PNG    
File Creat & Mknodat Event Example Output
--------------
.. image:: https://github.com/exeronn/auditd-python-parser/raw/main/images/filecreatemknodatevents.PNG    
File Open Event Example Output
--------------
.. image:: https://github.com/exeronn/auditd-python-parser/raw/main/images/fileopenevents.PNG    
User Auth Event Example Output
--------------
.. image:: https://github.com/exeronn/auditd-python-parser/raw/main/images/userauthevents.PNG   