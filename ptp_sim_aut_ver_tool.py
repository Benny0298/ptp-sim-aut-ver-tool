###--------------------------------------------------------------------------------------------------------------------------------------------------
### Automatic .pcap Verification Tool
###
### - in the context of Precision Time Protocol (PTP) Simulations
###
###--------------------------------------------------------------------------------------------------------------------------------------------------
###----- Info ---------------------------------------------------------------------------------------------------------------------------------------
###--------------------------------------------------------------------------------------------------------------------------------------------------
#
# Date:   January 11, 2022
#
# Author: Benedikt Welles
#
# File:   ptp_sim_aut_ver_tool.py
#
###--------------------------------------------------------------------------------------------------------------------------------------------------
###----- Description --------------------------------------------------------------------------------------------------------------------------------
###--------------------------------------------------------------------------------------------------------------------------------------------------
#
# This script is meant to facilitate an automatic verification procedure with regard to the PTP-traffic simulations, which result in .pcap files
#
###--------------------------------------------------------------------------------------------------------------------------------------------------
###----- Note(s) ------------------------------------------------------------------------------------------------------------------------------------
###--------------------------------------------------------------------------------------------------------------------------------------------------
#
#
#
###--------------------------------------------------------------------------------------------------------------------------------------------------
###----- ToDo(s) ------------------------------------------------------------------------------------------------------------------------------------
###--------------------------------------------------------------------------------------------------------------------------------------------------
#
#
#
###--------------------------------------------------------------------------------------------------------------------------------------------------
###----- FixMe(s) -----------------------------------------------------------------------------------------------------------------------------------
###--------------------------------------------------------------------------------------------------------------------------------------------------
#
#
#
###----- Imports ------------------------------------------------------------------------------------------------------------------------------------
# from asyncio import format_helpers # FIXME needed?
# from numpy import array_equal # FIXME needed?
import subprocess
import argparse
import pandas as pd

###--------------------------------------------------------------------------------------------------------------------------------------------------
###----- Constants ----------------------------------------------------------------------------------------------------------------------------------
###--------------------------------------------------------------------------------------------------------------------------------------------------

### types of pre-defined warnings
# represents warnings of type "zero timestamp found"
WTYPE_ZERO_TS = 1
# represents warnings of type "negative timestamp found"
WTYPE_NEGATIVE_TS = 2
# represents warnings of type "following timestamp smaller than current timestamp"
WTYPE_BACKWARDS_TS = 3
# represent warnings of type "unknown messageId"
WTYPE_UNKNOWN_MSG_ID = 4

### supported PTP messageIDs
# PTP Sync Messages (0x00)
PTP_MTYPE_SYNC = 0
# PTP Delay Request Messages (0x01)
PTP_MTYPE_DELAY_REQ = 1
# PTP Peer Delay Request Messages (0x02)
PTP_MTYPE_P_DELAY_REQ = 2
# PTP Peer Delay Response Messages (0x03)
PTP_MTYPE_P_DELAY_RESP = 3
# PTP Follow Up Messages (0x08)
PTP_MTYPE_FOLLOW_UP = 8
# PTP Delay Response Messages (0x09)
PTP_MTYPE_DELAY_RESP = 9
# PTP Peer Delay Response Follow Up Messages (0x0a)
PTP_MTYPE_P_DELAY_RESP_FU = 10
# PTP Announce Messages (0x0b)
PTP_MTYPE_ANNOUNCE = 11
# PTP Signalling Messages (0x0c)
PTP_MTYPE_SIGNALLING = 12
# PTP Management Messages (0x0d)
PTP_MTYPE_MANAGEMENT = 13

###--------------------------------------------------------------------------------------------------------------------------------------------------
###----- Global Variables ---------------------------------------------------------------------------------------------------------------------------
###--------------------------------------------------------------------------------------------------------------------------------------------------

### object for argparse usage
parser = argparse.ArgumentParser()

### represents wheter or not warnings of type "zero timestamp found" shall be suppressed or not
flagSuppressWarningZeroTS = False

### flags to represent which message types were found
msgFlagSync = False     # sync 
msgFlagDlyReq = False   # delay request
msgFlagFollUp = False   # follow up
msgFlagDlyResp = False  # delay response
msgFlagAnn = False      # announce 
msgFlagSig = False      # signalling
msgFlagMan = False      # management

### define list of valid args for tshark invocation
tsharkValidArgList = ["--", "-T", "-Y", "-r", "-e", "-E", ">"]

### list of arguments used to invoke tshark
tsharkInvokeList = []

### string to represent found eth.type value
# -e ip.src
# -e ipv6.src
# -e eth.src 
ethTypeUsed = ""

### string to represent version-specific name of field to identify type of PTP messages
# version 1.0.0 to 3.4.13 ... -e ptp.v2.messageid
# version 3.6.0 to 3.6.3  ... -e ptp.v2.messagetype
msgIdentifierUsed = ""

### keep track of unique ip-source values
uniqueSrcValues = []

### list of data frames seperating PTP messages per unique source
srcsList = []

### to keep track of unique message IDs
uniqueMsgIDs = []

### list of expected values for the field "logMP"
listExpectedLogMP = [0, 1]

### list of data frames per message type
listSyncDF = []
listDlyReqDF = []
listFollUpDF = []
listDlyRespDF = []
listAnnDF = []
listSigDF = []
listManDF = []

### preparing counter data frames for individual PTP message types
msgData = {"Sync":    [0],
            "DlyReq":  [0],
            "FollUp":  [0],
            "DlyResp": [0],
            "Ann":     [0],
            "Sig":     [0],
            "Man":     [0],
            "Total":   [0]}
msgCountDF = pd.DataFrame(msgData)
msgCountDF.index = ["msgCnt"]
# print(msgCountDF)

### list for logMP of different msg types
listSyncLogMP = []
listDlyReqLogMP = []
listFollUpLogMP = []
listDlyRespLogMP = []
listAnnLogMP = []
listSigLogMP = []
listManLogMP = []

### list for calculated avg msg interval
listSyncAvgInterval = []
listDlyReqAvgInterval = []
listFollUpAvgInterval = []
listDlyRespAvgInterval = []
listAnnAvgInterval = []
listSigAvgInterval = []
listManAvgInterval = []

# list for expected number of msgs, derived from
# - firstTS, lastTS, logMP 
listAnnMsgExpectedCnt = []

###--------------------------------------------------------------------------------------------------------------------------------------------------
###----- Sub-Routines -------------------------------------------------------------------------------------------------------------------------------
###--------------------------------------------------------------------------------------------------------------------------------------------------
  
###----- print defined warnings -----------------------------------------------
### print warning about a non-plausible timestamp within the generated data frame
# \param wType ... type of warning that shall be printed, supported values are
#                  - "WTYPE_ZERO_TS"        ... zero timestamp found
#                  - "WTYPE_NEGATIVE_TS"    ... negative timestamp found
#                  - "WTYPE_BACKWARDS_TS"   ... current timestamp lower than previous one
#                  - "WTYPE_UNKNOWN_MSG_ID" ... unknown messageId found
#
# \param df    ... data frame that holds the relevant information
#                  - must hold ["frameNum", "messageId", "flags", "ts"]
#
# \param idx   ... index to element of a given data frame
def print_specific_warning(wType, df, idx):
    print("-----")
    if(wType == WTYPE_ZERO_TS):
        if(flagSuppressWarningZeroTS == False): # TODO actually make use of this flag?
            print("warning:   zero timestamp")
            print("- frameNum: ", df["frameNum"][idx])
            print("- messageId:", df["messageId"][idx])
            print("- flags:    ", df["flags"][idx])
            print("- ts:       ", df["ts"][idx])
    elif(wType == WTYPE_NEGATIVE_TS):
        print("warning:   negative timestamp")
        print("- frameNum: ", df["frameNum"][idx])
        print("- ts:       ", df["ts"][idx])
    elif(wType == WTYPE_BACKWARDS_TS):
        print("warning:   current timestamp smaller than following")
        print("- frameNum: ", df["frameNum"][idx], "->", df["frameNum"][idx+1])
        print("- ts:       ", df["ts"][idx], "->", df["ts"][idx+1])
    elif(wType == WTYPE_UNKNOWN_MSG_ID):
        print("warning:   unknown messageId")
        print("- frameNum: ", df["frameNum"][idx])
        print("- messageId:", df["messageId"][idx])
    else:
        print("unknown warning type:", wType)
###----------------------------------------------------------------------------



###----- check for a number of potential reasons to print warnings ------------
# utilizes previously implemented print_specific_warning() function
#
# \param df             ... data frame that holds the relevant information
#
# \param warningCountDF ... data frame intended to present an overview about printed warnings
def check_ts(df, warningCountDF):
    ### check for zero ts
    # df.at[3, "ts"] = 0.0 # FIXME insert zero ts on purpose
    for idx in range(len(df["ts"])):
        if(df["ts"][idx] == 0):
            # print_specific_warning(WTYPE_ZERO_TS, df, idx) # TODO maybe add extra option to print these warnings or not
            warningCountDF["Zero"] += 1

    ### check for negative ts
    # df.at[4, "ts"] = -7.0 # FIXME insert negative ts on purpose
    for idx in range(len(df["ts"])):
        if(df["ts"][idx] < 0.0):
            print_specific_warning(WTYPE_NEGATIVE_TS, df, idx)
            warningCountDF["Negative"] += 1

    ### check for backwards ts between two consecutive PTP messages
    for idx in range(len(df["ts"]) - 1):
        if(df["ts"][idx] > df["ts"][idx+1]):
            print_specific_warning(WTYPE_BACKWARDS_TS, df, idx)
            warningCountDF["Backwards"] += 1
###----------------------------------------------------------------------------



###----- invoking tshark with a set of arguments ------------------------------
# function to invoke tshark with a given list of arguments
def invoke_tshark(argList):
  
  # create empty string for args to use
  invokeString = ""
    
  ### check length of given argList
  # len  < 0 ... should never happen
  # len == 0 ... invalid
  # len >= 1 ... check for valid args
  if(len(argList) == 0):
    raise ValueError("invalid argList: no args")
  elif(len(argList) >= 1):
    for str in argList: # loop to check entries
      for arg in tsharkValidArgList:
        if(str.startswith(arg)):
            invokeString += " " + str
  else:
    raise ValueError("error running tshark: len(argList) ==", str(len(argList)))
  
  # invoke tshark with created invokeString
  if(invokeString != ""):
    try:
      process = subprocess.run("tshark" + invokeString,
                               shell = True,
                               check = True,
                               universal_newlines = True).check_returncode()
    except ValueError:
      print("error running tshark, returncode:", process)
  else:
    raise ValueError("error running tshark")
###----------------------------------------------------------------------------



###----- check the installed tshark version -----------------------------------
# function to discern installed version of tshark/wireshark
# needed because of version specific differences such as
# --- different names for tshark fields, e.g. ptp.v2.messageid VS ptp.v2.messagetype
# --- different formatting of values of certain fields, e.g. hex-formatting VS strings
def check_tshark_version():
    ### string to represent name of field to identify PTP message types, dependant on installed wireshark/tshark version
    global msgIdentifierUsed
    
    ### run version cmd, pipe output to a .txt file
    invoke_tshark(["--version", ">output/tshark_ver.txt"])
    
    ### open .txt file for tshark version
    file_tshark_ver = open("output/tshark_ver.txt", "r")
    
    ### read the first line
    vLine = file_tshark_ver.readline()
    
    if("TShark (Wireshark) " in vLine):
        ### get part of string containing version number
        vNumString = vLine.split()[2] # TODO check if this is applicable to different wireshark/tshark versions
        
        ### split version string
        vNumString = vNumString.replace(".", " ").split()
        
        ### check length of version string
        if(len(vNumString) < 2):
            raise ValueError("invalid version string:", vNumString)
        elif(len(vNumString) == 3):
            ### extract major/minor/sub as integers
            vMajor = int(vNumString[0])
            vMinor = int(vNumString[1])
            vSub = int(vNumString[2])
        else:
            raise ValueError("invalid version string:", vNumString)
        
        ### check for version between 1.0.0 and 3.4.13
        if((vMajor >= 1 and vMajor <= 3) and (vMinor >= 0 and vMinor <= 4) and (vSub >= 0 and vSub <= 13)):
            msgIdentifierUsed = "ptp.v2.messageid"
        ### check for version between 3.6.0 and 3.6.3
        elif( (vMajor == 3) and (vMinor == 6) and (vSub >= 0 and vSub <= 3)):
            msgIdentifierUsed = "ptp.v2.messagetype"
        else:
            raise ValueError("no valid tshark version found")
    else:
        raise ValueError("problem discerning tshark version")
###----------------------------------------------------------------------------



###----- determine Layer2/IPv4/IPv6 -------------------------------------------        
# invoke tshark to analyse field eth.type
# create pandas dataframe for processing
# check dataframe for eligible ptp messages
# check value of field eth.type, set the String ethTypeUsed for further operations
def determine_eth_type(inputFileName):
    global ethTypeUsed
    
    invoke_tshark(["-Y \"ptp\"", "-T \"fields\" -2", "-r " + inputFileName, "-e eth.type", "> output/tshark-first.txt"])
        
    vData = pd.read_csv("output/tshark-first.txt",
                        sep = "\t",
                        header = None,
                        keep_default_na = True,
                        names = ["ethType"],
                        # index_col = "frameNum",
                        encoding = "utf-8")
    
    if(vData.empty == True):
        raise ValueError("no eligible PTP messages found within:" + inputFileName)
    else:
        ### check IPvX version of first PTP message
        # print(vData["ethType"][vData.first_valid_index()])
        ethTypeString = str(vData["ethType"][vData.first_valid_index()])
        
        if(ethTypeString.find("0800") != -1):
            ethTypeUsed = "ip.src"
        elif(ethTypeString.find("86dd") != -1):
            ethTypeUsed = "ipv6.src"
        elif(ethTypeString.find("8100") != -1):
            ethTypeUsed = "eth.src"
        else:
            raise ValueError("no valid eth.type found within:" + str(vData["ethType"][vData.first_valid_index]))
###----------------------------------------------------------------------------


###----- identifying unique source-IPs ----------------------------------------
# TODO add check whether or not ALL PTP messages are of same ethType
# - read all data from initially created file .txt file
# - store ip.src values in data frame ... srcData
# - store unique values for ip.src in ... uniqueSrcValues
def identify_ptp_sources(inputFileName):
    # to manipulate globally defined list
    global uniqueSrcValues
    
    # invoke tshark to check for sources of PTP messages
    # - store output in .txt file
    tsharkInvokeList = ["-Y \"ptp and not icmp\"", "-T \"fields\" -2", "-r " + inputFileName, "-E occurrence=f", "-e " + ethTypeUsed, "> output/tshark-first.txt"]
    invoke_tshark(tsharkInvokeList)

    # create pandas data frame from created .txt file
    srcData = pd.read_csv("output/tshark-first.txt",
                        sep = "\t",
                        header = None,
                        keep_default_na = True,
                        names = ["srcVal"],
                        # index_col = "frameNum",
                        encoding = "utf-8")
        
    # get unique values from created pandas data frame, store in list
    uniqueSrcValues = pd.unique(srcData["srcVal"])
    print("Unique Src Values: ", uniqueSrcValues)
###----------------------------------------------------------------------------


###----- create separate data frames for unique source-IPs --------------------
# invoke tshark for every unique ip.src found, store output in separate .txt files
# generate separate data frames for unique ip.src values, add data frames to list ... srcsList[]
def create_ptp_source_data_frames(inputFileName):
    global uniqueSrcValues
    global srcsList
    
    # invoke tshark to create separate input files
    for idx in range(len(uniqueSrcValues)):
        tsharkInvokeList = []
        tsharkInvokeList = ["-r " + inputFileName, "-Y \"ptp and " + ethTypeUsed + "==" + uniqueSrcValues[idx] + "\"", "-T \"fields\" -2", "-e frame.number", "-e " + msgIdentifierUsed, "> output/src" + str(idx) + "-out.txt"]
        invoke_tshark(tsharkInvokeList)

    # create separate data frames for the identified sources, append them to list srcsList
    fileName = ""
    for idx in range(len(uniqueSrcValues)):
        fileName = "output/src" + str(idx) + "-out.txt"
        srcsList.append(pd.read_csv(fileName,
                                    sep = "\t",
                                    header = None,
                                    keep_default_na = True,
                                    names = ["frameNum", "messageID"],
                                    # index_col = "frameNum",
                                    encoding = "utf-8"))
###----------------------------------------------------------------------------


###----- identifying unique PTP message IDs -----------------------------------
# read data from srcsList[]
# identify unique message IDs for identified srcVal in previously created srcsList
# store unique message IDs in list ... uniqueMsgIDs
# FIXME problem with version specific formatting of field <msgIdentifierUsed>
# - old versions (eg 3.2.3) ... ptp.v2.messageid=1
# - new versions (eg 3.6.3) ... ptp.v2.messagetype=0x01
def identify_ptp_msg_types():
    global srcsList
    global uniqueMsgIDs
    global msgFlagSync
    global msgFlagDlyReq
    global msgFlagFollUp
    global msgFlagDlyResp
    global msgFlagAnn
    global msgFlagSig
    global msgFlagMan
    # find and store unique message IDs
    for idx in range(len(srcsList)):
        uniqueMsgIDs.append(pd.unique(srcsList[idx]["messageID"]))
        # print("uniqueMsgIDs, srcsList[" + str(idx) + "]: ", uniqueMsgIDs)

    # check what PTP message types were found
    for arrayIdx in range(len(srcsList)):
        for itemIdx in range(len(uniqueMsgIDs[arrayIdx])):

            # FIXME problem with version specific formatting of field <msgIdentifierUsed>
            # - old versions (eg 3.2.3) ... ptp.v2.messageid=1
            # - new versions (eg 3.6.3) ... ptp.v2.messagetype=0x01
            # converting "0x0X" string to integer
            tempID = int(uniqueMsgIDs[arrayIdx][itemIdx], 16)
            uniqueMsgIDs[arrayIdx][itemIdx] = tempID
            # uniqueMsgIDs[arrayIdx][itemIdx] = int(uniqueMsgIDs[arrayIdx][itemIdx], 16) # doing conversion in one line

            if(uniqueMsgIDs[arrayIdx][itemIdx] == 0):
                msgFlagSync = True
            elif(uniqueMsgIDs[arrayIdx][itemIdx] == 1):
                msgFlagDlyReq = True
            elif(uniqueMsgIDs[arrayIdx][itemIdx] == 8):
                msgFlagFollUp = True
            elif(uniqueMsgIDs[arrayIdx][itemIdx] == 9):
                msgFlagDlyResp = True
            elif(uniqueMsgIDs[arrayIdx][itemIdx] == 11):
                msgFlagAnn = True
            elif(uniqueMsgIDs[arrayIdx][itemIdx] == 12):
                msgFlagSig = True
            elif(uniqueMsgIDs[arrayIdx][itemIdx] == 13):
                msgFlagMan = True

    # print uniqueMsgIDs as a whole
    print("Unique Msg IDs: ", uniqueMsgIDs)
###----------------------------------------------------------------------------


###----- get further information according to message type --------------------
# iterate through array of uniqueSrcValues and uniqueMsgIDs respectively to create .txt files for further processing
# add fields to tsharkInvokeList dependant on the identified PTP message type
def get_further_information(inputFileName, uniqueSrcValues, uniqueMsgIDs):

    for arrayIdx in range(len(uniqueSrcValues)):
        for itemIdx in range(len(uniqueMsgIDs[arrayIdx])):
            tsharkInvokeList = ["-r " + inputFileName, "-Y \"ptp and " + msgIdentifierUsed + "==" + str(uniqueMsgIDs[arrayIdx][itemIdx]) + " and " + ethTypeUsed + "==" + str(uniqueSrcValues[arrayIdx]) + "\"", "-T \"fields\" -2"]
            
            # FIXME use commas to seperate entries in tsharkInvokeList
            if(uniqueMsgIDs[arrayIdx][itemIdx] == PTP_MTYPE_SYNC):
                tsharkInvokeList.append("-e frame.number -e " + msgIdentifierUsed + " -e ptp.v2.flags -e ptp.v2.sequenceid -e ptp.v2.logmessageperiod -e ptp.v2.sdr.origintimestamp.seconds -e ptp.v2.sdr.origintimestamp.nanoseconds")
            elif(uniqueMsgIDs[arrayIdx][itemIdx] == PTP_MTYPE_DELAY_REQ):
                tsharkInvokeList.append("-e frame.number -e " + msgIdentifierUsed + " -e ptp.v2.flags -e ptp.v2.sequenceid -e ptp.v2.logmessageperiod -e ptp.v2.sdr.origintimestamp.seconds -e ptp.v2.sdr.origintimestamp.nanoseconds")
            elif(uniqueMsgIDs[arrayIdx][itemIdx] == PTP_MTYPE_FOLLOW_UP):
                tsharkInvokeList.append("-e frame.number -e " + msgIdentifierUsed + " -e ptp.v2.flags -e ptp.v2.sequenceid -e ptp.v2.logmessageperiod -e ptp.v2.fu.preciseorigintimestamp.seconds -e ptp.v2.fu.preciseorigintimestamp.nanoseconds")
            elif(uniqueMsgIDs[arrayIdx][itemIdx] == PTP_MTYPE_DELAY_RESP):
                tsharkInvokeList.append("-e frame.number -e " + msgIdentifierUsed + " -e ptp.v2.flags -e ptp.v2.sequenceid -e ptp.v2.logmessageperiod -e ptp.v2.dr.receivetimestamp.seconds -e ptp.v2.dr.receivetimestamp.nanoseconds")
            elif(uniqueMsgIDs[arrayIdx][itemIdx] == PTP_MTYPE_ANNOUNCE):
                tsharkInvokeList.append("-e frame.number -e " + msgIdentifierUsed + " -e ptp.v2.flags -e ptp.v2.sequenceid -e ptp.v2.logmessageperiod -e ptp.v2.an.origintimestamp.seconds -e ptp.v2.an.origintimestamp.nanoseconds")
            elif(uniqueMsgIDs[arrayIdx][itemIdx] == PTP_MTYPE_SIGNALLING):
                tsharkInvokeList.append("-e frame.number -e " + msgIdentifierUsed + " -e ptp.v2.flags -e ptp.v2.sequenceid -e ptp.v2.logmessageperiod -e ptp.v2.sig.tlv.tlvType")
            elif(uniqueMsgIDs[arrayIdx][itemIdx] == PTP_MTYPE_MANAGEMENT):
                tsharkInvokeList.append("-e frame.number -e " + msgIdentifierUsed + " -e ptp.v2.flags")
            else:
                print("unknown message ID: ", uniqueMsgIDs[arrayIdx][itemIdx])
                continue
            
            tsharkInvokeList.append("> output/src" + str(arrayIdx) + "-msgID" + str(uniqueMsgIDs[arrayIdx][itemIdx]) + "-out.txt")
            
            invoke_tshark(tsharkInvokeList)
###----------------------------------------------------------------------------


###----- create individual data frames for different message IDs --------------
# go through previously created .txt files to create individual pandas data frames
# append generated data frames to lists differentiated by type of PTP message
def create_ptp_message_data_frames():
    global uniqueSrcValues
    global uniqueMsgIDs
    global listSyncDF
    global listDlyReqDF
    global listFollUpDF
    global listDlyRespDF
    global listAnnDF
    global listSigDF
    
    ### iterate through uniqueIpSrcs and uniqueMsgIDs
    for arrayIdx in range(len(uniqueSrcValues)):
        for itemIdx in range(len(uniqueMsgIDs[arrayIdx])):
            ### prepare fileName
            fileName = ""
            fileName += "output/src" + str(arrayIdx) + "-msgID" + str(uniqueMsgIDs[arrayIdx][itemIdx]) + "-out.txt"
            # print("fileName: ", fileName)
            
            ### create data frames according to found message IDs
            if(uniqueMsgIDs[arrayIdx][itemIdx] == PTP_MTYPE_SYNC):
                syncData = pd.read_csv(fileName,
                                    sep = "\t",
                                    header = None,
                                    keep_default_na = True,
                                    names = ["frameNum", "messageID", "flags", "seqID", "logMP", "ts_s", "ts_ns"],
                                    # index_col = "frameNum",
                                    encoding = "utf-8")
                # append to list
                listSyncDF.append(syncData)
                
            elif(uniqueMsgIDs[arrayIdx][itemIdx] == PTP_MTYPE_DELAY_REQ):
                delayReqData = pd.read_csv(fileName,
                                        sep = "\t",
                                        header = None,
                                        keep_default_na = True,
                                        names = ["frameNum", "messageID", "flags", "seqID", "logMP", "ts_s", "ts_ns"],
                                        # index_col = "frameNum",
                                        encoding = "utf-8")
                # append to list
                listDlyReqDF.append(delayReqData)
                
            elif(uniqueMsgIDs[arrayIdx][itemIdx] == PTP_MTYPE_FOLLOW_UP):
                followUpData = pd.read_csv(fileName,
                                        sep = "\t",
                                        header = None,
                                        keep_default_na = True,
                                        names = ["frameNum", "messageID", "flags", "seqID", "logMP", "ts_s", "ts_ns"],
                                        # index_col = "frameNum",
                                        encoding = "utf-8")
                # append to list
                listFollUpDF.append(followUpData)
                
            elif(uniqueMsgIDs[arrayIdx][itemIdx] == PTP_MTYPE_DELAY_RESP):
                delayRespData = pd.read_csv(fileName,
                                            sep = "\t",
                                            header = None,
                                            keep_default_na = True,
                                            names = ["frameNum", "messageID", "flags", "seqID", "logMP", "ts_s", "ts_ns"],
                                            # index_col = "frameNum",
                                            encoding = "utf-8")
                # append to list
                listDlyRespDF.append(delayRespData)
                
            elif(uniqueMsgIDs[arrayIdx][itemIdx] == PTP_MTYPE_ANNOUNCE):
                announceData = pd.read_csv(fileName,
                                        sep = "\t",
                                        header = None,
                                        keep_default_na = True,
                                        names = ["frameNum", "messageID", "flags", "seqID", "logMP", "ts_s", "ts_ns"],
                                        # index_col = "frameNum",
                                        encoding = "utf-8")
                # append to list
                listAnnDF.append(announceData)
                
            elif(uniqueMsgIDs[arrayIdx][itemIdx] == PTP_MTYPE_SIGNALLING):
                sigData = pd.read_csv(fileName,
                                    sep = "\t",
                                    header = None,
                                    keep_default_na = True,
                                    names = ["frameNum", "messageID", "flags", "seqID", "logMP", "tlvType"],
                                    # index_col = "frameNum",
                                    encoding = "utf-8")
                # append to list
                listSigDF.append(sigData)
                
            elif(uniqueMsgIDs[arrayIdx][itemIdx] == PTP_MTYPE_MANAGEMENT):
                manData = pd.read_csv(fileName,
                                    sep = "\t",
                                    header = None,
                                    keep_default_na = True,
                                    names = ["frameNum", "messageId", "flags"],
                                    # index_col = "frameNum",
                                    encoding = "utf-8")
                # append to list
                listManDF.append(manData)
                
            else:
                print("unknown message ID: ", uniqueMsgIDs[arrayIdx][itemIdx])
                continue
###----------------------------------------------------------------------------


###----- PTP message type specific calculations -----------------------------------
# TODO determine sensible analysis for signnaling messages
# TODO determine sensible analysis for management messages
# PTP message type specific calculations
# - get msg count
# - get logMP # TODO check if logMP stays the same for ALL messages of one type
# - append calculated avgIntervall to list of respective ptpMsgType
def ptp_msg_type_specific_calcs(ptpMsgType, listDF):
    
    global msgCountDF
    
    # iterate through given list
    for arrayIdx in range(len(listDF)):
        # TODO current special cases for signalling/management msgs, as they dont hold time stamps
        if(ptpMsgType == PTP_MTYPE_SIGNALLING):
            msgCountDF["Sig"] += len(listDF[arrayIdx]["frameNum"])
        elif(ptpMsgType == PTP_MTYPE_MANAGEMENT):
            msgCountDF["Man"] += len(listDF[arrayIdx]["frameNum"])
        else:
            ### shared calculations
            # create empty column for combined ts
            pd.DataFrame.insert(listDF[arrayIdx], len(listDF[arrayIdx].columns), "ts", float(0.0))

            # calc ts from ts_s and ts_ns
            for idx in range(len(listDF[arrayIdx])):
                ts = listDF[arrayIdx]["ts_s"][idx] + listDF[arrayIdx]["ts_ns"][idx] * 10 ** (-9)
                listDF[arrayIdx].at[idx, "ts"] = ts
            # print(listDF[arrayIdx])

            # get unique sequence IDs
            msgTypeUniqueSeqID = len(pd.unique(listDF[arrayIdx]["seqID"]))
            # print(msgTypeUniqueSeqID)

            # get information about ts
            firstTS = listDF[arrayIdx]["ts"][listDF[arrayIdx]["ts"].first_valid_index()]
            lastTS  = listDF[arrayIdx]["ts"][listDF[arrayIdx]["ts"].last_valid_index()]
            diffTS  = lastTS - firstTS
            
            ### msg type specific calculations
            # sync
            if(ptpMsgType == PTP_MTYPE_SYNC):
                global listSyncLogMP
                global listSyncAvgInterval
               
                msgCountDF["Sync"] += len(listDF[arrayIdx]["frameNum"])
                listSyncLogMP.append(listDF[arrayIdx]["logMP"][listDF[arrayIdx]["logMP"].first_valid_index()])
                listSyncAvgInterval.append(diffTS / msgTypeUniqueSeqID)
                
            # delay request
            elif(ptpMsgType == PTP_MTYPE_DELAY_REQ):
                global listDlyReqLogMP
                global listDlyReqAvgInterval
                
                msgCountDF["DlyReq"] += len(listDF[arrayIdx]["frameNum"])
                listDlyReqLogMP.append(listDF[arrayIdx]["logMP"][listDF[arrayIdx]["logMP"].first_valid_index()])           
                listDlyReqAvgInterval.append(diffTS / msgTypeUniqueSeqID)

            # follow up
            elif(ptpMsgType == PTP_MTYPE_FOLLOW_UP):
                global listFollUpLogMP
                global listFollUpAvgInterval
                
                msgCountDF["FollUp"] += len(listDF[arrayIdx]["frameNum"])
                listFollUpLogMP.append(listDF[arrayIdx]["logMP"][listDF[arrayIdx]["logMP"].first_valid_index()])           
                listFollUpAvgInterval.append(diffTS / msgTypeUniqueSeqID)
            
            # delay response
            elif(ptpMsgType == PTP_MTYPE_DELAY_RESP):
                global listDlyRespLogMP
                global listDlyRespAvgInterval
                
                msgCountDF["DlyResp"] += len(listDF[arrayIdx]["frameNum"])
                listDlyRespLogMP.append(listDF[arrayIdx]["logMP"][listDF[arrayIdx]["logMP"].first_valid_index()])           
                listDlyRespAvgInterval.append(diffTS / msgTypeUniqueSeqID)
            
            # announce
            elif(ptpMsgType == PTP_MTYPE_ANNOUNCE):
                global listAnnLogMP
                global listAnnAvgInterval
                
                msgCountDF["Ann"] += len(listDF[arrayIdx]["frameNum"])
                listAnnLogMP.append(listDF[arrayIdx]["logMP"][listDF[arrayIdx]["logMP"].first_valid_index()])           
                listAnnAvgInterval.append(diffTS / msgTypeUniqueSeqID)
###--------------------------------------------------------------------------------


###----- print warning overview ---------------------------------------------------
# check for potential reasons to print a warning, like
# - Zero TS
# - Negative TS
# - Backwards TS between two following Messages
# - Not yet defined reasons due to unknown problems
def print_warning_overview(warningCountDF):
    print("--------------------------------------------------------------------")
    print("--- Warning(s) -----------------------------------------------------")
    print("--------------------------------------------------------------------")
    print("- Sync -")
    if(msgFlagSync == True):
        for arrayIdx in range(len(listSyncDF)):
            check_ts(listSyncDF[arrayIdx], warningCountDF)
    print("--------------------------------------------------------------------")
    print("- DlyReq -")
    if(msgFlagDlyReq == True):
        for arrayIdx in range(len(listDlyReqDF)):
            check_ts(listDlyReqDF[arrayIdx], warningCountDF)
            # iterate through seqID to find possible irregularities
            for itemIdx in range(len(listDlyReqDF[arrayIdx])-1):
                if(listDlyReqDF[arrayIdx]["seqID"][itemIdx]+1 != listDlyReqDF[arrayIdx]["seqID"][itemIdx+1]):
                    warningCountDF["SeqID"] += 1
                    print("")
                    print("Irregular seqID:")
                    print("- frameNum =", listDlyReqDF[arrayIdx]["frameNum"][itemIdx], "-> frameNum =", listDlyReqDF[arrayIdx]["frameNum"][itemIdx+1])
                    print("- seqID =", listDlyReqDF[arrayIdx]["seqID"][itemIdx], "-> seqID =", listDlyReqDF[arrayIdx]["seqID"][itemIdx+1])
            # compare number of DlyReq and DlyResp messages
            if(msgCountDF["DlyReq"][msgCountDF["DlyReq"].last_valid_index()] < msgCountDF["DlyResp"][msgCountDF["DlyResp"].last_valid_index()]):
                # print("DlyResp Msg missing")
                warningCountDF["CntMismatch"] += 1
                print("")
                print("Missing DlyReq Msg:")
                print("- Cnt DlyReq:  ", msgCountDF["DlyReq"][msgCountDF["DlyReq"].last_valid_index()])
                print("- Cnt DlyResp: ", msgCountDF["DlyResp"][msgCountDF["DlyResp"].last_valid_index()])

    print("--------------------------------------------------------------------")
    print("- FollowUp -")
    if(msgFlagFollUp == True):
        for arrayIdx in range(len(listFollUpDF)):
            check_ts(listFollUpDF[arrayIdx], warningCountDF)
    print("--------------------------------------------------------------------")
    print("- DlyResp -")
    if(msgFlagDlyResp == True):
        for arrayIdx in range(len(listDlyRespDF)):
            check_ts(listDlyRespDF[arrayIdx], warningCountDF)
            # iterate through seqID to find possible irregularities
            for itemIdx in range(len(listDlyRespDF[arrayIdx])-1):
                if(listDlyRespDF[arrayIdx]["seqID"][itemIdx]+1 != listDlyRespDF[arrayIdx]["seqID"][itemIdx+1]):
                    warningCountDF["SeqID"] += 1
                    print("")
                    print("Irregular seqID:")
                    print("- frameNum =", listDlyRespDF[arrayIdx]["frameNum"][itemIdx], "-> frameNum =", listDlyRespDF[arrayIdx]["frameNum"][itemIdx+1])
                    print("- seqID =", listDlyRespDF[arrayIdx]["seqID"][itemIdx], "-> seqID =", listDlyRespDF[arrayIdx]["seqID"][itemIdx+1])
            # compare number of DlyReq and DlyResp messages
            if(msgCountDF["DlyReq"][msgCountDF["DlyReq"].last_valid_index()] > msgCountDF["DlyResp"][msgCountDF["DlyResp"].last_valid_index()]):
                # print("DlyResp Msg missing")
                warningCountDF["CntMismatch"] += 1
                print("")
                print("Missing DlyResp Msg:")
                print("- Cnt DlyReq:  ", msgCountDF["DlyReq"][msgCountDF["DlyReq"].last_valid_index()])
                print("- Cnt DlyResp: ", msgCountDF["DlyResp"][msgCountDF["DlyResp"].last_valid_index()])
                
    print("--------------------------------------------------------------------")
    print("- Ann -")
    if(msgFlagAnn == True):
        for arrayIdx in range(len(listAnnDF)):
            check_ts(listAnnDF[arrayIdx], warningCountDF)
    print("--------------------------------------------------------------------")
###-------------------------------------------------------------------------------- 


###----- print final overview -----------------------------------------------------
def print_final_overview(warningCountDF):
    global msgCountDF
    
    print("--- Msg Type Specific Overview -------------------------------------")
    ### Sync Message Overview
    if(msgFlagSync == True):
        ### display actual results
        print("--------------------------------------------------------------------")
        print("--- sync info ---")

        for arrayIdx in range(len(listSyncDF)):
            print("")
            print("src:", str(uniqueSrcValues[arrayIdx]))
            ### expected avg interval VS actual avg interval
            # listSyncLogMP[arrayIdx] = 127 # FIXME inserting LogMP for tests
            syncAvgIntervalExpected = 0.0
            firstTS = listSyncDF[arrayIdx]["ts"][listSyncDF[arrayIdx]["ts"].first_valid_index()]
            lastTS = listSyncDF[arrayIdx]["ts"][listSyncDF[arrayIdx]["ts"].last_valid_index()]
            print("first ts:", firstTS, "s")
            print("last ts: ", lastTS, "s")
            if(-8 <= listSyncLogMP[arrayIdx] <= 8): # FIXME magic numbers for limits
                syncAvgIntervalExpected = 2.0 ** float(listSyncLogMP[arrayIdx])
                syncExpectedNumMsgs = (lastTS - firstTS) / syncAvgIntervalExpected
                print("Sync Log MP:", listSyncLogMP[arrayIdx])
                print("Expected Num Sync Msgs: ", syncExpectedNumMsgs) # FIXME leave it like this or add number to a second row in msgCountDF
                print("Expected Avg Sync Interval:  ", syncAvgIntervalExpected, "s")
                print("Calculated Avg Sync Interval:", listSyncAvgInterval, "s")
            else:
                print("Unexpected Log MP:", listSyncLogMP[arrayIdx])
       
    ### DelayReq Message Overview 
    if(msgFlagDlyReq == True):
        ### display actual results
        print("--------------------------------------------------------------------")
        print("--- dely req info ---")

        for arrayIdx in range(len(listDlyReqDF)):
            print("")
            print("src:", str(uniqueSrcValues[arrayIdx]))
            ### expected avg interval VS actual avg interval
            # listDlyReqLogMP[arrayIdx] = 127 # FIXME inserting LogMP for tests
            dlyReqAvgIntervalExpected = 0.0
            print("first ts:", listDlyReqDF[arrayIdx]["ts"][listDlyReqDF[arrayIdx]["ts"].first_valid_index()], "s")
            print("last ts: ", listDlyReqDF[arrayIdx]["ts"][listDlyReqDF[arrayIdx]["ts"].last_valid_index()], "s")
            if(0 <= listDlyReqLogMP[arrayIdx] <= 5): # FIXME magic numbers for limits
                print("DlyReq LogMP:", listDlyReqLogMP[arrayIdx])
                dlyReqAvgIntervalExpected = 2.0 ** float(listDlyReqLogMP[arrayIdx])
                print("Expected Avg DlyReq Interval:  ", dlyReqAvgIntervalExpected, "s")
            else:
                print("Unexpected Log MP:", listDlyReqLogMP[arrayIdx])
            print("Calculated Avg DlyReq Interval:", listDlyReqAvgInterval[arrayIdx], "s")
    
    ### Follow Up Message Overview
    if(msgFlagFollUp == True):
        ### display actual results
        print("--------------------------------------------------------------------")
        print("--- follow up info ---")

        for arrayIdx in range(len(listFollUpDF)):
            print("")
            print("src:", str(uniqueSrcValues[arrayIdx]))
            ### expected avg interval VS actual avg interval
            # listFollUpLogMP[arrayIdx] = 127 # FIXME inserting LogMP for tests
            follUpAvgIntervalExpected = 0.0
            print("first ts:", listFollUpDF[arrayIdx]["ts"][listFollUpDF[arrayIdx]["ts"].first_valid_index()], "s")
            print("last ts: ", listFollUpDF[arrayIdx]["ts"][listFollUpDF[arrayIdx]["ts"].last_valid_index()], "s")
            if(-8 <= listFollUpLogMP[arrayIdx] <= 8): # FIXME magic numbers for limits # FIXME what are the actual limits?
                print("FollUp LogMP:", listFollUpLogMP[arrayIdx])
                follUpAvgIntervalExpected = 2.0 ** float(listFollUpLogMP[arrayIdx])
                print("Expected Avg FollUp Interval:  ", follUpAvgIntervalExpected, "s")
            else:
                print("Unexpected Log MP:", listFollUpLogMP[arrayIdx])
            print("Calculated Avg FollUp Interval:", listFollUpAvgInterval[arrayIdx], "s")
    
    ### DelayResp Message Overview
    if(msgFlagDlyResp == True):
        ### display actual results
        print("--------------------------------------------------------------------")
        print("--- delay response info ---")

        for arrayIdx in range(len(listDlyRespDF)):
            print("")
            print("src:", str(uniqueSrcValues[arrayIdx]))
            ### expected avg interval VS actual avg interval
            # listDlyRespLogMP[arrayIdx] = 127 # FIXME inserting LogMP for tests
            dlyRespAvgIntervalExpected = 0.0
            print("first ts:", listDlyRespDF[arrayIdx]["ts"][listDlyRespDF[arrayIdx]["ts"].first_valid_index()], "s")
            print("last ts: ", listDlyRespDF[arrayIdx]["ts"][listDlyRespDF[arrayIdx]["ts"].last_valid_index()], "s")
            if(0 <= listDlyRespLogMP[arrayIdx] <= 5): # FIXME magic numbers for limits
                print("DlyResp LogMP:", listDlyRespLogMP[arrayIdx])
                dlyRespAvgIntervalExpected = 2.0 ** float(listDlyRespLogMP[arrayIdx])
                print("Expected Avg DlyResp Interval:  ", dlyRespAvgIntervalExpected, "s")
            else:
                print("Unexpected Log MP:", listDlyRespLogMP[arrayIdx])
            print("Calculated Avg DlyResp Interval:", listDlyRespAvgInterval[arrayIdx], "s")
    
    ### Announce Message Overview
    if(msgFlagAnn == True):
        ### display actual results
        print("--------------------------------------------------------------------")
        print("--- announce info ---")

        for arrayIdx in range(len(listAnnDF)):
            print("")
            print("src:", str(uniqueSrcValues[arrayIdx]))
            ### expected avg interval VS actual avg interval
            # listAnnLogMP[arrayIdx] = 127 # FIXME inserting LogMP for tests
            annAvgIntervalExpected = 0.0
            print("first ts:", listAnnDF[arrayIdx]["ts"][listAnnDF[arrayIdx]["ts"].first_valid_index()], "s")
            print("last ts: ", listAnnDF[arrayIdx]["ts"][listAnnDF[arrayIdx]["ts"].last_valid_index()], "s")
            if(-7 <= listAnnLogMP[arrayIdx] <= 4): # FIXME magic numbers for limits
                print("Ann LogMP:", listAnnLogMP[arrayIdx])
                annAvgIntervalExpected = 2.0 ** float(listAnnLogMP[arrayIdx])
                print("Expected Avg Ann Interval:  ", annAvgIntervalExpected, "s")
            else:
                print("Unexpected Log MP:", listAnnLogMP[arrayIdx])
            print("Calculated Avg Ann Interval:", listAnnAvgInterval[arrayIdx], "s")
        
    ### Signalling Message Overview
    if(msgFlagSig == True):
        ### display actual results
        print("--------------------------------------------------------------------")
        print("--- signalling info ---")
        print("TODO determine sensible analysis for signalling messages")
        
        for arrayIdx in range(len(listSigDF)):
            print("")
            print("src" + str(arrayIdx) + ": " + str(uniqueSrcValues[arrayIdx]))
      
    ### Management Message Overview
    if(msgFlagMan == True):
        ### display actual results
        print("--------------------------------------------------------------------")
        print("--- management info ---")
        print("TODO determine sensible analysis for management messages")
        
        for arrayIdx in range(len(listManDF)):
            print("")
            print("src" + str(arrayIdx) + ": " + str(uniqueSrcValues[arrayIdx]))
        
    ### calculate total number of PTP messages found
    msgCountDF["Total"] = msgCountDF["Ann"] + msgCountDF["DlyReq"] + msgCountDF["DlyResp"] + msgCountDF["FollUp"] + msgCountDF["Man"] + msgCountDF["Sig"] + msgCountDF["Sync"]
    
    print("--------------------------------------------------------------------")
    print("--- Msg Count Overview ---")
    print(msgCountDF)        
    
    print("--------------------------------------------------------------------")
    print("--- Warning Count Overview ---")
    print(warningCountDF)
###--------------------------------------------------------------------------------



###--------------------------------------------------------------------------------------------------------------------------------------------------
###----- Main Body ----------------------------------------------------------------------------------------------------------------------------------
###--------------------------------------------------------------------------------------------------------------------------------------------------
def main():
    ###----- cmd line arguements ----------------------------------------------
    ### - define and parse cmd line arguments

    ### define arguments
    # -h ... (predefined) show help about this script
    # -v ... show version and general information about this script
    # -i ... input file
    parser.add_argument("-v", "--version", action="version", version="%(prog)s 3.0", help="show program version and exit.")
    parser.add_argument("-i", "--inFile", type=str, required=True)

    ### parse given arguments
    args = parser.parse_args()
    
    ### call function to analyse specified input file
    parseFile(args.inFile)
###----------------------------------------------------------------------------

def parseFile(inputFileName:str):
    
    ### prepare counters for potential warnings regarding different possible problems
    # TODO maybe add more dimensions to this data frame, to easily determine the origin of a warning
    warningData = {"Zero":        [0],
                   "Negative":    [0],
                   "Backwards":   [0],
                   "SeqID":       [0],
                   "CntMismatch": [0],
                   "Other":       [0]}
    warningCountDF = pd.DataFrame(warningData)
    warningCountDF.index = ["wCnt"]
    # print(warningCountDF)
    
    ###----- check tshark version -------------------------------------------------
    # function to discern installed version of tshark/wireshark
    # needed because of version specific differences such as
    # --- different names for tshark fields, e.g. ptp.v2.messageid VS ptp.v2.messagetype
    # --- different formatting of values of certain fields, e.g. hex-formatting VS strings
    check_tshark_version()
    ###----------------------------------------------------------------------------
    
    ###----- determine Layer2/IPv4/IPv6 ------------------------------------------- 
    # invoke tshark to analyse field eth.type
    # create pandas dataframe for processing
    # check dataframe for eligible ptp messages
    # check value of field eth.type, set appropriate ethTypeFlag for further operations 
    determine_eth_type(inputFileName)
    ###----------------------------------------------------------------------------
    
    ###----- identifying unique source-IPs ----------------------------------------
    # TODO add check whether or not ALL PTP messages are of same ethType
    # read all data from initially created file .txt file
    # store ip.src values in data frame ... srcData
    # store unique values for ip.src in ... uniqueSrcValues
    identify_ptp_sources(inputFileName)
    ###----------------------------------------------------------------------------
    
    ###----- create separate data frames for unique source-IPs --------------------
    # invoke tshark for every unique ip.src found, store output in separate .txt files
    # generate separate data frames for unique ip.src values, add data frames to list ... srcsList[]
    create_ptp_source_data_frames(inputFileName)
    ###----------------------------------------------------------------------------


    ###----- identifying unique PTP message IDs -----------------------------------
    # read data from srcsList[]
    # identify unique message IDs for identified srcVal in previously created srcsList
    # store unique message IDs in list ... uniqueMsgIDs
    identify_ptp_msg_types()
    ###----------------------------------------------------------------------------


    ###----- get further information according to message type --------------------
    # invoke tshark while iterating through uniqueSrcValues and uniqueMsgIDs, extracting information according to PTP message type
    # store information in seperate .txt files
    get_further_information(inputFileName, uniqueSrcValues, uniqueMsgIDs)
    ###----------------------------------------------------------------------------


    ###----- create individual data frames for different message IDs --------------
    # go through previously created .txt files to create individual pandas data frames
    # append generated data frames to lists differentiated by type of PTP message
    create_ptp_message_data_frames()
    ###----------------------------------------------------------------------------
    
    ###----- sync message calculations --------------------------------------------
    # check if sync messages were found
    if(msgFlagSync == True):
        ptp_msg_type_specific_calcs(PTP_MTYPE_SYNC, listSyncDF)
    ###----------------------------------------------------------------------------

    ###----- delay Req message calculations ---------------------------------------
    # check if delay request messages were found
    if(msgFlagDlyReq == True):
        ptp_msg_type_specific_calcs(PTP_MTYPE_DELAY_REQ, listDlyReqDF)
    ###----------------------------------------------------------------------------

    ###----- follow up message calculations ---------------------------------------
    # check if follow up messages were found
    if(msgFlagFollUp == True):
        ptp_msg_type_specific_calcs(PTP_MTYPE_FOLLOW_UP, listFollUpDF)
    ###----------------------------------------------------------------------------

    ###----- delay Res message calculations ---------------------------------------
    # check if delay response messages were found
    if(msgFlagDlyResp == True):
        ptp_msg_type_specific_calcs(PTP_MTYPE_DELAY_RESP, listDlyRespDF)
    ###----------------------------------------------------------------------------

    ###----- announce message calculations ----------------------------------------
    # check if announce messages were found
    if(msgFlagAnn == True):
        ptp_msg_type_specific_calcs(PTP_MTYPE_ANNOUNCE, listAnnDF)
    ###----------------------------------------------------------------------------

    ###----- signalling message calculations --------------------------------------
    ### check if signalling messages were found
    if(msgFlagSig == True):
        ptp_msg_type_specific_calcs(PTP_MTYPE_SIGNALLING, listSigDF)
    ###----------------------------------------------------------------------------
    
    ###----- management message calculations --------------------------------------
    ### check if management messages were found
    if(msgFlagMan == True):
        ptp_msg_type_specific_calcs(PTP_MTYPE_MANAGEMENT, listManDF)
    ###----------------------------------------------------------------------------
    
    ###----- print warning overview -----------------------------------------------
    print_warning_overview(warningCountDF)
    ###----------------------------------------------------------------------------
    
    ###----- print final overview -------------------------------------------------
    print_final_overview(warningCountDF)
    ###----------------------------------------------------------------------------

if __name__ == "__main__":
    main()