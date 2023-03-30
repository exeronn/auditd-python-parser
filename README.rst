auditd-python-parser
========

An in development python library to parse raw auditd events generated on a linux system. This is done only using the auditd.log* files and doesn't require the use of ausearch or similar. The logs can also be parsed on a Windows system.

The library tries to keep to the key fields for each event type and generates additional fields to enable process ancestry (process GUIDs) and event linkage similar to how SysmonForLinux does. Some events are enriched where possible such as the network events by adding the process commandline to the network connection where possible.

To use you import the library in the src folder and then call parsedata(data) from it which will return the values. Currently it returns dfprocessevents, dfnetworkevents.

.. code:: python

    import auditdparser 
    f = open("auditd.log", "r")
    rawdata = f.read()
    f.close()   
    dfprocessevents, dfnetworkevents = auditdparser.parsedata(rawdata)
