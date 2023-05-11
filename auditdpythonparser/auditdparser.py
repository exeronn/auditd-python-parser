import datetime
import shlex
import uuid
from hashlib import md5
import pandas as pd

def _parseprocessevent(processevents, commandline, eventjson):
    '''
    A private function to parse process events from raw auditd events
    ---Inputs---
    * processevents: an array containing the process events we've already parsed into json
    * commandline: the processed commandline from the arg events in the execve event
    * eventjson: the full event in JSON format to parse & process into the processevents array

    ---Returns---
    * processevents: an array containing the process events we've already parsed - showing just the fields we want
    '''
    #remove the end space we add when parsing the arg commands
    eventjson["commandline"] = commandline.rstrip(" ")
    #attempt to get the timestamp via either the syscall or the execve event, syscall is the first priority
    try:
        ts = eventjson["msg"].replace("audit(", "").replace(")", "").split(":")[0]
    except:
        ts = eventjson["EXECVE-msg"].replace("audit(", "").replace(")", "").split(":")[0]
    #convert the timestamp to a readable time
    readabletime = datetime.datetime.utcfromtimestamp(float(ts)).strftime('%Y-%m-%d %H:%M:%S.%f')
    eventjson["Time"] = readabletime
    #we don't want to return all fields due to how many their are, we can't display them easily. So make a new dictionary with the fields we want.
    eventjsondisp = dict()
    #set the time field
    eventjsondisp["Time"] = eventjson["Time"]
    #set the exe field - the file path
    try:
        eventjsondisp["exe"] = eventjson["exe"]
    except:
        eventjsondisp["exe"] = "UNKNOWN"
    #set the commandline which we tidied up earlier
    eventjsondisp["commandline"] = eventjson["commandline"]
    #set the process ID
    try:
        eventjsondisp["pid"] = eventjson["pid"]
    except:
        eventjsondisp["pid"] = "UNKNOWN"
    #set the parent process ID
    try:
        eventjsondisp["ppid"] = eventjson["ppid"]
    except:
        eventjsondisp["ppid"] = "UNKNOWN"
    #set the key that was set by auditd - typically which rule logged it
    try:
        eventjsondisp["key"] = eventjson["key"]
    except:
        eventjsondisp["key"] = "UNKNOWN"
    #set the session ID - useful for tracking back session activity
    try:
        eventjsondisp["ses"] = eventjson["ses"]
    except:
        eventjsondisp["ses"] = "UNKNOWN"
    #set if it was sucessful or not
    try:
        eventjsondisp["success"] = eventjson["success"]
    except:
        eventjsondisp["success"] = "UNKNOWN"
    #set the username that was used for the process
    try:
        eventjsondisp["uid"] = eventjson["UID"]
    except:
        eventjsondisp["uid"] = "UNKNOWN"
    #append this row to the array
    processevents.append(eventjsondisp)
    #return the array
    return processevents

def _parsenetworkevents(networkevents, eventjson):
    '''
    A private function to parse network events from raw auditd events
    ---Inputs---
    * networkevents: an array containing the network events we've already parsed into json
    * eventjson: the full event in JSON format to parse & process into the networkevents array

    ---Returns---
    * networkevents: an array containing the process events we've already parsed - showing just the fields we want
    '''
    #attempt to get the timestamp via the syscall event
    ts = eventjson["msg"].replace("audit(", "").replace(")", "").split(":")[0]
    #convert the timestamp to a readable time
    readabletime = datetime.datetime.utcfromtimestamp(float(ts)).strftime('%Y-%m-%d %H:%M:%S.%f')
    eventjson["Time"] = readabletime
    #we don't want to return all fields due to how many their are, we can't display them easily. So make a new dictionary with the fields we want.
    eventjsondisp = dict()
    #set the time field
    eventjsondisp["Time"] = eventjson["Time"]
    #if the even has a network address in it (including localhost or all) then we want to parse it
    if "SOCKADDR-laddr" in eventjson:
        #set the IP address field
        try:
            eventjsondisp["address"] = eventjson["SOCKADDR-laddr"]
        except:
            eventjsondisp["address"] = "UNKNOWN"
        #set the port field
        try:
            eventjsondisp["port"] = eventjson["SOCKADDR-lport"]
        except:
            eventjsondisp["port"] = "UNKNOWN"
        #set the username field
        try:
            eventjsondisp["uid"] = eventjson["UID"]
        except:
            eventjsondisp["uid"] = "UNKNOWN"
        #set the process ID field
        try:
            eventjsondisp["pid"] = eventjson["pid"]
        except:
            eventjsondisp["pid"] = "UNKNOWN"
        #set the parent process ID field
        try:
            eventjsondisp["ppid"] = eventjson["ppid"]
        except:
            eventjsondisp["ppid"] = "UNKNOWN"
        #set the exe field - the file path
        try:
            eventjsondisp["exe"] = eventjson["exe"]
        except:
            eventjsondisp["exe"] = "UNKNOWN"
        #set the key that was set by auditd - typically which rule logged it
        try:
            eventjsondisp["key"] = eventjson["key"]
        except:
            eventjsondisp["key"] = "UNKNOWN"
        #append this row to the array
        networkevents.append(eventjsondisp)
    #return the array
    return networkevents

def _parsefilecreateevents(filecevents, eventjson):
    '''
    A private function to parse file create events from raw auditd events
    ---Inputs---
    * filecevents: an array containing the network events we've already parsed into json
    * eventjson: the full event in JSON format to parse & process into the networkevents array

    ---Returns---
    * filecevents: an array containing the process events we've already parsed - showing just the fields we want
    '''
    #attempt to get the timestamp via the syscall event
    ts = eventjson["msg"].replace("audit(", "").replace(")", "").split(":")[0]
    #convert the timestamp to a readable time
    readabletime = datetime.datetime.utcfromtimestamp(float(ts)).strftime('%Y-%m-%d %H:%M:%S.%f')
    eventjson["Time"] = readabletime
    #we don't want to return all fields due to how many their are, we can't display them easily. So make a new dictionary with the fields we want.
    eventjsondisp = dict()
    #set the time field
    eventjsondisp["Time"] = eventjson["Time"]
    
    #set the first file path value
    try:
        eventjsondisp["filepath0"] = eventjson["PATH-0-name"][1:-1] #remove the surroundingg quotes with [1:-1]
    except:
        eventjsondisp["filepath0"] = "UNKNOWN"
    #set the second file path value
    try:
        eventjsondisp["filepath1"] = eventjson["PATH-1-name"][1:-1] #remove the surroundingg quotes with [1:-1]
    except:
        eventjsondisp["filepath1"] = "UNKNOWN"        
    eventjsondisp["filepath"] = eventjsondisp["filepath1"] #set this now & we'll overwrite it later if we need to
    #check if the full path is in the second path value
    if not eventjsondisp["filepath1"].startswith("/"):
        if eventjsondisp["filepath1"] != "UNKNOWN": #Ignore it if the path is unknown
            if eventjsondisp["filepath0"] != "UNKNOWN": #Ignore it if the path is unknown
                eventjsondisp["filepath"] = "{0}/{1}".format(eventjsondisp["filepath0"], eventjsondisp["filepath1"])
    #set the username field
    try:
        eventjsondisp["uid"] = eventjson["UID"]
    except:
        eventjsondisp["uid"] = "UNKNOWN"
    #set the process ID field
    try:
        eventjsondisp["pid"] = eventjson["pid"]
    except:
        eventjsondisp["pid"] = "UNKNOWN"
    #set the parent process ID field
    try:
        eventjsondisp["ppid"] = eventjson["ppid"]
    except:
        eventjsondisp["ppid"] = "UNKNOWN"
    #set the exe field - the file path
    try:
        eventjsondisp["exe"] = eventjson["exe"]
    except:
        eventjsondisp["exe"] = "UNKNOWN"
    #set the key that was set by auditd - typically which rule logged it
    try:
        eventjsondisp["key"] = eventjson["key"]
    except:
        eventjsondisp["key"] = "UNKNOWN"
        
    #set the success state, this is more likely to fail than other events due to permissions
    try:
        eventjsondisp["success"] = eventjson["success"]
    except:
        eventjsondisp["success"] = "UNKNOWN"
        
    #were recording multiple syscalls in this table, record which one made this event
    try:
        eventjsondisp["syscall"] = eventjson["SYSCALL"]
    except:
        eventjsondisp["syscall"] = "UNKNOWN"
    #append this row to the array
    filecevents.append(eventjsondisp)
    #return the array
    return filecevents

def _parsefileopenatevents(fileopenatevents, eventjson):
    '''
    A private function to parse file openat events from raw auditd events
    ---Inputs---
    * fileopenatevents: an array containing the network events we've already parsed into json
    * eventjson: the full event in JSON format to parse & process into the networkevents array

    ---Returns---
    * fileopenatevents: an array containing the process events we've already parsed - showing just the fields we want
    '''
    #attempt to get the timestamp via the syscall event
    ts = eventjson["msg"].replace("audit(", "").replace(")", "").split(":")[0]
    #convert the timestamp to a readable time
    readabletime = datetime.datetime.utcfromtimestamp(float(ts)).strftime('%Y-%m-%d %H:%M:%S.%f')
    eventjson["Time"] = readabletime
    #we don't want to return all fields due to how many their are, we can't display them easily. So make a new dictionary with the fields we want.
    eventjsondisp = dict()
    #set the time field
    eventjsondisp["Time"] = eventjson["Time"]
    
    #set the first file path value
    try:
        eventjsondisp["filepath0"] = eventjson["PATH-0-name"][1:-1] #remove the surrounding quotes with [1:-1]
    except:
        eventjsondisp["filepath0"] = "UNKNOWN"
    #set the second file path value
    try:
        eventjsondisp["filepath1"] = eventjson["PATH-1-name"][1:-1] #remove the surrounding quotes with [1:-1]
    except:
        eventjsondisp["filepath1"] = "N/A"        
    eventjsondisp["filepath"] = eventjsondisp["filepath1"] #set this now & we'll overwrite it later if we need to
    #check if the full path is in the second path value
    if not eventjsondisp["filepath1"].startswith("/"):
        if eventjsondisp["filepath1"] != "N/A": #Ignore it if the path is unknown
            if eventjsondisp["filepath0"] != "UNKNOWN": #Ignore it if the path is unknown
                eventjsondisp["filepath"] = "{0}/{1}".format(eventjsondisp["filepath0"], eventjsondisp["filepath1"])
        else:
            eventjsondisp["filepath"] = "{0}".format(eventjsondisp["filepath0"])
    
    try:
        eventjsondisp["filetype0"] = eventjson["PATH-0-nametype"]
    except:
        eventjsondisp["filetype0"] = "UNKNOWN"
    #set the second file path value
    try:
        eventjsondisp["filetype1"] = eventjson["PATH-1-nametype"]
    except:
        eventjsondisp["filetype1"] = "N/A"
    #set the username field
    try:
        eventjsondisp["uid"] = eventjson["UID"]
    except:
        eventjsondisp["uid"] = "UNKNOWN"
    #set the process ID field
    try:
        eventjsondisp["pid"] = eventjson["pid"]
    except:
        eventjsondisp["pid"] = "UNKNOWN"
    #set the parent process ID field
    try:
        eventjsondisp["ppid"] = eventjson["ppid"]
    except:
        eventjsondisp["ppid"] = "UNKNOWN"
    #set the exe field - the file path
    try:
        eventjsondisp["exe"] = eventjson["exe"]
    except:
        eventjsondisp["exe"] = "UNKNOWN"
    #set the key that was set by auditd - typically which rule logged it
    try:
        eventjsondisp["key"] = eventjson["key"]
    except:
        eventjsondisp["key"] = "UNKNOWN"
        
    #set the success state, this is more likely to fail than other events due to permissions
    try:
        eventjsondisp["success"] = eventjson["success"]
    except:
        eventjsondisp["success"] = "UNKNOWN"
        
    #were recording multiple syscalls in this table, record which one made this event
    try:
        eventjsondisp["syscall"] = eventjson["SYSCALL"]
    except:
        eventjsondisp["syscall"] = "UNKNOWN"
    #append this row to the array
    fileopenatevents.append(eventjsondisp)
    #return the array
    return fileopenatevents

def _parseuserauthevents(userauthevents, eventjson):
    '''
    A private function to parse file openat events from raw auditd events
    ---Inputs---
    * userauthevents: an array containing the auth events we've already parsed into json
    * eventjson: the full event in JSON format to parse & process into the networkevents array

    ---Returns---
    * userauthevents: an array containing the auth events we've parsed - showing just the fields we want
    '''
    #attempt to get the timestamp via the syscall event
    ts = eventjson["msg"].replace("audit(", "").replace(")", "").split(":")[0]
    #convert the timestamp to a readable time
    readabletime = datetime.datetime.utcfromtimestamp(float(ts)).strftime('%Y-%m-%d %H:%M:%S.%f')
    eventjson["Time"] = readabletime
    #we don't want to return all fields due to how many their are, we can't display them easily. So make a new dictionary with the fields we want.
    eventjsondisp = dict()
    #set the time field
    eventjsondisp["Time"] = eventjson["Time"]
    
    #set the username the auth is running under
    try:
        eventjsondisp["source_user"] = eventjson["USER_AUTH-UID"][1:-1] #remove quotes
    except:
        eventjsondisp["source_user"] = "UNKNOWN"
        
    #set the target username
    try:
        eventjsondisp["target_user"] = eventjson["USER_AUTH-acct"][1:-1] #remove quotes
    except:
        eventjsondisp["target_user"] = "UNKNOWN"
        
    #set the source address
    try:
        eventjsondisp["src_addr"] = eventjson["USER_AUTH-addr"]
    except:
        eventjsondisp["src_addr"] = "UNKNOWN"
        
    #set the source hostname
    try:
        eventjsondisp["src_host"] = eventjson["USER_AUTH-hostname"]
    except:
        eventjsondisp["src_host"] = "UNKNOWN"
        
    #set the auth terminal
    try:
        eventjsondisp["auth_terminal"] = eventjson["USER_AUTH-terminal"]
    except:
        eventjsondisp["auth_terminal"] = "UNKNOWN"
        
    #set the auth success
    try:
        eventjsondisp["auth_success"] = eventjson["USER_AUTH-res"][:-1] #remove a trailing quote
    except:
        eventjsondisp["auth_success"] = "UNKNOWN"
        
    #set the process ID field
    try:
        eventjsondisp["pid"] = eventjson["pid"]
    except:
        eventjsondisp["pid"] = "UNKNOWN"
    #set the parent process ID field
    try:
        eventjsondisp["ppid"] = eventjson["ppid"]
    except:
        eventjsondisp["ppid"] = "UNKNOWN"
    #set the exe field - the file path
    try:
        eventjsondisp["exe"] = eventjson["exe"]
    except:
        eventjsondisp["exe"] = "UNKNOWN"
    #set the key that was set by auditd - typically which rule logged it
    try:
        eventjsondisp["key"] = eventjson["key"]
    except:
        eventjsondisp["key"] = "UNKNOWN"
        
    #append this row to the array
    userauthevents.append(eventjsondisp)
    #return the array
    return userauthevents

def _processchain(processevents):
    '''
    A private function to parse the process events & add some ancestry via GUIDs to them
    ---Inputs---
    * processevents: an array containing the process events we parsed earlier

    ---Returns---
    * dfprocesseventsguid: array - an array of the process events with the following additional fields: guid, parentguid, parentcommandline, parentexe
    * procguidmaptime: dict() PID->timestamp->GUID - to parse in time order finding the first match where the event time is greater than the process start time. 
                       Compare the exe files where possible to reduce false matches when the process hasn't been recorded.
    * processkeymappingcl: dict() - GUID->commandline
    * processkeymappingexe: dict() - GUID->exe
    '''
    #convert the array to a pandas dataframe
    dfprocessevents = pd.DataFrame.from_dict(processevents)
    #set the time column
    dfprocessevents["Time"] = pd.to_datetime(dfprocessevents["Time"], yearfirst=True, format="%Y-%m-%d %H:%M:%S.%f")
    #set variables for key->value items we want to track
    processkeymapping = dict() #pid -> GUID (kept current & overwritten as a PID is reused)
    processkeymappingcl = dict() #GUID->commandline
    processkeymappingexe = dict() #GUID->exe
    procguidmaptime = dict()    #PID->timestamp->GUID - to parse in time order finding the first match where the event time is greater than the process start time. 
                                #Compare the exe files where possible to reduce false matches when the process hasn't been recorded.
    #set the array for events once the GUID data has been processed
    dfprocesseventsguid = []
    for key, event in dfprocessevents.sort_values(by='Time', ascending=True).iterrows(): #iterate over the process events in time order
        #generate the repeatble GUIDs for the processes by hashing the process start time, process exe path and process commandline
        seed = "{0},{1},{2}".format(event["Time"], event["exe"], event["commandline"])
        seed = md5(seed.encode('utf-8')).hexdigest() # use MD5 as we need 128 bits for the UUID seed
        eventuuid = str(uuid.UUID(int=int(seed, 16))) #It's a base16 number (hex)
        event["guid"] = eventuuid
        #Save the GUIDs and other metadata for quick rereival
        processkeymapping[event["pid"]] = eventuuid
        processkeymappingcl[eventuuid] = event["commandline"]
        processkeymappingexe[eventuuid] = event["exe"]
        #try and find the parent GUID. If it cannot be found (not recorded or the tree root process) then assign a GuID of all zero's, with the PID overwriting the end to make it semi unique
        try:
            event["parentguid"] = processkeymapping[event["ppid"]]
        except:
            basezero = "00000000-0000-0000-0000-000000000000" #set the base of all zeros
            basezero = basezero[:-len(event["ppid"])] #remove enough zero's to append the PID & keep the same length string
            event["parentguid"] = "{0}{1}".format(basezero, event["ppid"]) #merge the PID onto the end
        #try and set the parent commandline if possible
        try:
            event["parentcommandline"] = processkeymappingcl[event["parentguid"]]
        except:
            event["parentcommandline"] = "UNKNOWN"
        #try and set the parent exe if possible
        try:
            event["parentexe"] = processkeymappingexe[event["parentguid"]]
        except:
            event["parentexe"] = "UNKNOWN"
        #append the event to the GUID array as we've no parsed all the required variables
        dfprocesseventsguid.append(event)
        #generate the lookup for when we want to lookup events such as network connections to get the process GUID that made it
        try:
            #does the PID exist?
            a = procguidmaptime[str(event["pid"])]
            del a
        except:
            #If not create it and assign the value a dict
            procguidmaptime[str(event["pid"])] = dict()
            
        #The time is ms so we'll assume it's unique for PID reuse purposes (it may not be but should be very rare) and create that, assignign the process GUID for that timestamp
        procguidmaptime[str(event["pid"])][event["Time"].timestamp()] = event["guid"]
        
    #return the process array and 3 variables we want to re use in the future in other functions
    return dfprocesseventsguid, procguidmaptime, processkeymappingcl, processkeymappingexe

def _getguidfrompid(pid, eventtimestamp, procguidmaptime, processkeymappingexe, eventexe):
    '''
    A private function to get the GUID for a PID provided
    ---Inputs---
    * pid: the process ID we want to GUID for
    * eventtimestamp: the hopefully ms timestamp for the event we want the GUID for (e.g. timestamp of the network connection or file create)
    * procguidmaptime: dict() PID->timestamp->GUID - to parse in time order finding the first match where the event time is greater than the process start time. 
                       Compare the exe files where possible to reduce false matches when the process hasn't been recorded.
    * processkeymappingexe: dict() - GUID->exe
    * eventexe: str() - the path for the event exe file recorded in the syscall event. if one isn't present set it to False. This is to sanity check the lookup where possible

    ---Returns---
    * procguid: str() - the GUID for the event or the one generated from the basezero data if we can't fine one.
    '''

    basezero = "00000000-0000-0000-0000-000000000000" #set the base of all zeros
    procguid = basezero #set the procguid to this as default so we can always return something
    #if we don't have any lookups for the PID then generate a GUID off the base zero record
    if pid not in procguidmaptime:
        if pid != "NaT": #this shouldn't happen anymore, but just incase
            basezero = basezero[:-len(pid)] #remove enough zero's to append the PID & keep the same length string
            procguid = "{0}{1}".format(basezero, pid) #merge the PID onto the end
    else:
        procfound = False #we have lookups for the PID, however we only want to send the first one back as anymore will be incorrect. Set this to False not and then True on the first match
        for proctime in sorted(procguidmaptime[pid]): #sort the events in time order
            if (float(eventtimestamp) > float(proctime)) and not procfound: #if the event happend after the process start and is the first one, then look at recording it.
                procfound = True #regardless if the exe lookup matches, this is the first process after the event in order that matched. Anymore will be false correlations
                if eventexe: #if we don't have eventexe set to False, we want to compare it
                    #lookup the eventexe for the mathed process GUID and if it matches the one from the syscall it's more likely to be correct
                    if processkeymappingexe[procguidmaptime[pid][proctime]] == eventexe: 
                        procguid = procguidmaptime[pid][proctime]  #set the procguid
                else:
                    #if we don't have an exe to compare, just set it anyway, with a higher false correlation rate
                    procguid = procguidmaptime[pid][proctime]
    return str(procguid) #return the guid
            
def _networkchain(networkevents, processkeymappingexe, processkeymappingcl, procguidmaptime):
    '''
    A private function to add process GUID and commandline columns to the network events
    ---Inputs---
    * networkevents: an array of parsed network events
    * processkeymappingexe: dict() - GUID->exe
    * processkeymappingcl: dict() - GUID->commandline
    * procguidmaptime: dict() PID->timestamp->GUID - to parse in time order finding the first match where the event time is greater than the process start time. 
                       Compare the exe files where possible to reduce false matches when the process hasn't been recorded.

    ---Returns---
    * networkeventsguid: an array containing the network evens with the process GUID and process commandline columns set
    '''
    dfnetworkevents = pd.DataFrame.from_dict(networkevents) #convert it to a pandas dataframe
    networkeventsguid = [] #set the base array for the modified events
    if len(networkevents) > 0: #check there are records, if not return an empty array
        dfnetworkevents["Time"] = pd.to_datetime(dfnetworkevents["Time"], yearfirst=True, format="%Y-%m-%d %H:%M:%S.%f") #set the time column
        for key, event in dfnetworkevents.sort_values(by='Time', ascending=True).iterrows(): #iterate over the network events, in time order
            event["processguid"] = _getguidfrompid(str(event["pid"]), event["Time"].timestamp(), procguidmaptime, processkeymappingexe, str(event["exe"])) #get the process guid from the _getguidfrompid function
            #attempt to set the process commandline by looking up the process GUID against processkeymappingcl (dict: GUID->commandline)
            try:
                event["processcommandline"] = processkeymappingcl[event["processguid"]]
            except:
                event["processcommandline"] = "UNKNOWN"

            networkeventsguid.append(event) #append the updated columns to the new array
    return networkeventsguid #return the new array

def parsedata(eventdata):
    '''
    A public function to parse the raw auditd events. Submit the raw events as a string of 1 or more auditd files.
    ---Inputs---
    * eventdata: a string of 1 or more raw audid.log files

    ---Returns---
    * resultdict: a dictionary containing the Pandas dataframes of the results.
                    process - Process events
                    network - Network events
    '''
    #fields from sysmonforlinux data - which ones to look at intially to replicate functionality using auditd
    #process = [] 
    #network = []
    #filec = []
    #filed = []
    #proca = []
    #which syscalls do we want to dedicate processing to. Later on add a catchall for any recorded events with some basic fields
    types = []
    types.append("EXECVE")
    types.append("SOCKADDR")
    types.append("creat") #syscall
    types.append("mknodat") #syscall
    types.append("openat") #syscall
    types.append("USER_AUTH")

    processevents = [] #process event array
    networkevents = [] #network event array
    filecreateevents = [] #file create event array
    fileopenatevents = [] #file openat event array
    userauthevents = []

    syscallevents = set() #internal - to record unique syscalls to see which events might need parsing

    data = eventdata.split("type=PROCTITLE") #PROCTITLE is the start of a new multiline event so split on this
    for event in data: #loop through each event
        interest = False #do we want to parse this?
        syscall = '' #what's the syscall
        eventdata = '' #the string to hold the event data for the syscall we care about
        eventtypesave = '' #record the event type we care about when we see it as we loop through each line & the event type changes
        pathevents = [] # to save path results to, multiple per syscall are common
        for row in event.split("\n"): #loop through each line
            if "type=" in row: #if the event has a type set then parse it
                eventtype = row.split("type=")[1].split(" ")[0] #split on = and then take the first string before the next space
                if eventtype in types: #if this is an event type we want to parse, then parse it
                    interest = True #we want to parse it
                    eventdata = row.replace("\x1d", " ") #this hex value was causing some funny behaviour, so remove it
                    eventtypesave = eventtype #save the event type to lookup later in the parent loop
                if eventtype == "SYSCALL":
                    syscall = row.replace("\x1d", " ") #record the syscall data
                if eventtype == "PATH":
                    pathevents.append(row.replace("\x1d", " "))                    

        eventjson = dict() #base dictionary for the key->value lookup
        syscall = shlex.split(syscall, posix=False) #split the syscall event into an array. Splits on space, preserving spaces in quotes
        for row in syscall: #loop over each syscall value
            splitindex = row.find("=") #find the first = to split on, incase "=" is in an event somewhere
            key = row[0:splitindex] #set the key off the index
            value = row[(splitindex + 1):] #set the value off the index
            eventjson[key] = value #generate the key->value event
        try:
            syscallevents.add(eventjson["SYSCALL"]) #if the SYSCALL key is present, add it to the unique lookup of syscalls seens
        except:
            pass
        
        #try and set the syscall
        try:
            syscall = eventjson["SYSCALL"]
        except:
            syscall = "UNKNOWN"
            
        if syscall in types:
            interest = True
        
        if interest: #if we want to parse it

            eventdata = shlex.split(eventdata, posix=False) #split the event of interest (e.g. execve) into an array. Splits on space, preserving spaces in quotes
            commandline = '' #set the base to generate the commandline
            for row in sorted(eventdata): #sort the keys as we want to parse the commandline in order (a0, a1, a2, etc)
                splitindex = row.find("=") #find the first = to split on, incase "=" is in an event somewhere
                key = "{0}-{1}".format(eventtypesave, row[0:splitindex]) #set the key off the index. To prevent variable overwrite concat it with the eventtype at the start e.g. EXECVE
                value = row[(splitindex + 1):] #set the value off the index
                eventjson[key] = value #generate the key->value event
                if key.startswith("EXECVE-a"): #if it's a process commandline arguement then parse it
                    if key != "EXECVE-argc": #we don't care about argcount for this
                        commandline += str(value[1:-1]) + " " #append the arg to the end of the commandline string
                        
            if len(pathevents) > 0:
                item = 0
                for pathentry in pathevents:
                    pathentrysplit = shlex.split(pathentry, posix=False) #split the event of interest (e.g. paths) into an array. Splits on space, preserving spaces in quotes
                    for row in sorted(pathentrysplit):
                        splitindex = row.find("=")
                        key = "{0}".format(row[0:splitindex]) #set the key off the index.
                        value = row[(splitindex + 1):] #set the value off the index
                        if key == "item":
                            item = value
                            break #we don't need to process anymore
                            
                    for row in sorted(pathentrysplit):
                        splitindex = row.find("=")
                        key = "PATH-{0}-{1}".format(item, row[0:splitindex]) #set the key off the index. To prevent variable overwrite concat it with the eventtype at the start e.g. EXECVE
                        value = row[(splitindex + 1):] #set the value off the index
                        eventjson[key] = value #generate the key->value event
                        
                    #key = "PATH-{0}-{1}".format(eventtypesave, row[0:splitindex]) #set the key off the index. To prevent variable overwrite concat it with the eventtype at the start e.g. EXECVE
                    #<todo>
            #if it's a process (execve) do the process processing
            if syscall == "execve":
                processevents = _parseprocessevent(processevents, commandline, eventjson)
            #if it's a network event then parse the network event
            if syscall == "connect":
                networkevents = _parsenetworkevents(networkevents, eventjson)
            if (syscall == "creat") or (syscall == "mknodat"):
                filecreateevents = _parsefilecreateevents(filecreateevents, eventjson)
            if syscall == "openat":
                fileopenatevents = _parsefileopenatevents(fileopenatevents, eventjson)
            #the syscall is openat which is not useful in this case, looking for the auth property gives us the event we want
            if "USER_AUTH-type" in eventjson.keys():
                userauthevents = _parseuserauthevents(userauthevents, eventjson)

    #generate the process chain and lookup variables                
    dfprocesseventsguid, procguidmaptime, processkeymappingcl, processkeymappingexe = _processchain(processevents)
    
    #assign the processguid and process commandline to the network events
    networkevents = _networkchain(networkevents, processkeymappingexe, processkeymappingcl, procguidmaptime)
    
    #assign the processguid and process commandline to the file create events
    filecreateevents = _networkchain(filecreateevents, processkeymappingexe, processkeymappingcl, procguidmaptime)
    
    #assign the processguid and process commandline to the file openat events
    fileopenatevents = _networkchain(fileopenatevents, processkeymappingexe, processkeymappingcl, procguidmaptime)
    
    #assign the processguid and process commandline to the user auth events
    userauthevents = _networkchain(userauthevents, processkeymappingexe, processkeymappingcl, procguidmaptime)
    
    #convert the process events to a pandas dataframe
    dfprocessevents = pd.DataFrame.from_dict(dfprocesseventsguid)
    del dfprocesseventsguid
    
    #convert the network events to a pandas dataframe
    dfnetworkevents = pd.DataFrame.from_dict(networkevents)
    del networkevents
    
    #convert the filecreate events to a pandas dataframe
    dffilecreateevents = pd.DataFrame.from_dict(filecreateevents)
    del filecreateevents
    
    dffileopenatevents = pd.DataFrame.from_dict(fileopenatevents)
    del fileopenatevents
    
    dfuserauthevents = pd.DataFrame.from_dict(userauthevents)
    del userauthevents
    
    #assign the result dictionary & add the results    
    resultdict = dict()
    resultdict["process"] = dfprocessevents
    resultdict["network"] = dfnetworkevents
    resultdict["filecreate"] = dffilecreateevents
    resultdict["fileopenat"] = dffileopenatevents
    resultdict["userauth"] = dfuserauthevents
    
    #return the results
    return resultdict 