#!/usr/bin/env python
import os
import cmd
import readline
from scapy.all import *

################################################################
# Scapy tool based on python cmd template found here:
# http://code.activestate.com/recipes/280500-console-built-with-cmd-object/
################################################################


class Console(cmd.Cmd):

    def __init__(self):
        cmd.Cmd.__init__(self)
        self.prompt = "pktparser>>> "
        self.intro  = """
           /$$         /$$                                                                
          | $$        | $$                                                                
  /$$$$$$ | $$   /$$ /$$$$$$    /$$$$$$   /$$$$$$   /$$$$$$   /$$$$$$$  /$$$$$$   /$$$$$$ 
 /$$__  $$| $$  /$$/|_  $$_/   /$$__  $$ |____  $$ /$$__  $$ /$$_____/ /$$__  $$ /$$__  $$
| $$  \ $$| $$$$$$/   | $$    | $$  \ $$  /$$$$$$$| $$  \__/|  $$$$$$ | $$$$$$$$| $$  \__/
| $$  | $$| $$_  $$   | $$ /$$| $$  | $$ /$$__  $$| $$       \____  $$| $$_____/| $$      
| $$$$$$$/| $$ \  $$  |  $$$$/| $$$$$$$/|  $$$$$$$| $$       /$$$$$$$/|  $$$$$$$| $$      
| $$____/ |__/  \__/   \___/  | $$____/  \_______/|__/      |_______/  \_______/|__/      
| $$                          | $$                                                        
| $$                          | $$                                                        
|__/                          |__/                                                        
 
Command line tool for pulling interesting info out of pcaps.
Start by pointing pktparser to a pcap file with 'load file_name.pcap'

    pktparser>>> load 20170815.pcap
    <bound method PacketList.summary of <hidden_captured-intelligence.pcap: TCP:817 UDP:225 ICMP:0 Other:28>>
    pktparser>>> dnsunique
    Extracting unique dns queries now....
    wpad.localdomain.
    webchat.freenode.net.
    131.134.168.192.in-addr.arpa.
    bantha.deathstar.empire.localdomain.
    pktparser>>> 


Type 'help' for a list of commands. 


        """
        ## defaults to None

    ## Command definitions ##
    def do_hist(self, args):
        """Print a list of commands that have been entered"""
        print self._hist

    def do_exit(self, args):
        """Exits from the console"""
        return -1

    ## Command definitions to support Cmd object functionality ##
    def do_EOF(self, args):
        """Exit on system end of file character"""
        return self.do_exit(args)

    def do_shell(self, args):
        """Pass command to a system shell when line begins with '!' or 'shell'
For example: shell ifconfig"""
        os.system(args)

    def do_help(self, args):
        """Get help on commands
           'help' or '?' with no arguments prints a list of commands for which help is available
           'help <command>' or '? <command>' gives help on <command>
        """
        ## The only reason to define this method is for the help text in the doc string
        cmd.Cmd.do_help(self, args)

    ## Override methods in Cmd object ##
    def preloop(self):
        """Initialization before prompting user for commands.
           Despite the claims in the Cmd documentaion, Cmd.preloop() is not a stub.
        """
        cmd.Cmd.preloop(self)   ## sets up command completion
        self._hist    = []      ## No history yet
        self._locals  = {}      ## Initialize execution namespace for user
        self._globals = {}

    def postloop(self):
        """Take care of any unfinished business.
           Despite the claims in the Cmd documentaion, Cmd.postloop() is not a stub.
        """
        cmd.Cmd.postloop(self)   ## Clean up command completion
        print "Exiting..."

    def precmd(self, line):
        """ This method is called after the line has been input but before
            it has been interpreted. If you want to modifdy the input line
            before execution (for example, variable substitution) do it here.
        """
        self._hist += [ line.strip() ]
        return line

    def postcmd(self, stop, line):
        """If you want to stop the console, return something that evaluates to true.
           If you want to do some post command processing, do it here.
        """
        return stop

    def emptyline(self):    
        """Do nothing on empty input line"""
        pass

    def default(self, line):       
        """Called on an input line when the command prefix is not recognized.
           In that case we execute the line as Python code.
        """
        try:
            exec(line) in self._locals, self._globals
        except Exception, e:
            print e.__class__, ":", e

##############################################################################################
# PCAP Analysis Stuff
############################################################################################## 
    #############################################################
    # load pcap for analysis:
    ############################################################# 
    
    def do_load(self,args):
        """Load a pcap for analysis. Syntax is 'load my_capture.pcap'"""
        if len(args) == 0:
            print "Syntax is 'load my_capture.pcap'"
        else:
            try:
                pcap = args
                global pcap_for_analysis
                pcap_for_analysis = rdpcap(pcap)
                print pcap_for_analysis.summary
                global pcap_len
                pcap_len = len(pcap_for_analysis)
            except:
                print 'File not found. Try using the shell command to find your file.'
                
    #############################################################
    # Print all packets:
    ############################################################# 
    
    def do_printall(self,args):
        """Print the short summary of all packets in the pcap. Results are displayed as: packet number,timestamp,connection"""
        try:
            pcap_for_analysis
            if len(args) == 0:        
                for packet_number in range(pcap_len):
                    packet = pcap_for_analysis[packet_number]
                    print str(packet_number) + ',' + packet.summary()
            else:
                print 'No args needed, just load a pcap then run command.'
        except:
            print "You need to load a pcap first. Try 'help load'" 
    #############################################################
    # hexdump a packet by number:
    ############################################################# 
    def do_pkthex(self, args):
        """Get the hexdump of a packet by the sequence number"""
        try:
            pcap_for_analysis
            if len(args) == 0:        
                print "Please provide a packet number 'pkthex 342'" 
            else:
                packet_number = args
                packet = pcap_for_analysis[int(packet_number)]
                hexdump(packet)
        except:
            print "You need to load a pcap first. Try 'help load'" 
            
    #############################################################
    # Get packet payload by number:
    ############################################################# 
    def do_pktpayload(self, args):
        """Get the payload of a packet by the sequence number"""
        try:
            pcap_for_analysis
            if len(args) == 0:        
                print "Please provide a packet number 'hexdump 342'" 
            else:
                packet_number = args
                packet = pcap_for_analysis[int(packet_number)]
                print packet.payload
        except:
            print "You need to load a pcap first. Try 'help load'"    
            
    #############################################################
    # Get packet details by number:
    ############################################################# 
    def do_pktshow(self, args):
        """Show the expanded scapy view of a packet by sequence number"""
        try:
            pcap_for_analysis
            if len(args) == 0:        
                print "Please provide a packet number 'pktshow 342'" 
            else:
                packet_number = args
                packet = pcap_for_analysis[int(packet_number)]
                packet.show()
        except:
            print "You need to load a pcap first. Try 'help load'"      
    #############################################################
    # Get packet connection summary info:
    ############################################################# 
    def do_pktsumm(self, args):
        """Show brief connection details for the packet"""
        try:
            pcap_for_analysis
            if len(args) == 0:        
                print "Please provide a packet number 'pktsumm 342'" 
            else:
                packet_number = args
                packet = pcap_for_analysis[int(packet_number)]
                packet.summary()
        except:
            print "You need to load a pcap first. Try 'help load'"     
    #############################################################
    # Print all stateful sessions. 
    ############################################################# 
    def do_stateful(self, args):
        """Get the total number of stateful connections in the pcap. 
Use 'stateful all' to see each stateful connection"""
        def full_duplex(p):
            sess = "Other"
            if 'Ether' in p:
                if 'IP' in p:
                    if 'TCP' in p:
                        sess = str(sorted(["TCP", p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport],key=str))
                    elif 'UDP' in p:
                        sess = str(sorted(["UDP", p[IP].src, p[UDP].sport, p[IP].dst, p[UDP].dport] ,key=str))
                    elif 'ICMP' in p:
                        sess = str(sorted(["ICMP", p[IP].src, p[IP].dst, p[ICMP].code, p[ICMP].type, p[ICMP].id] ,key=str)) 
                    else:
                        sess = str(sorted(["IP", p[IP].src, p[IP].dst, p[IP].proto] ,key=str)) 
                elif 'ARP' in p:
                    sess = str(sorted(["ARP", p[ARP].psrc, p[ARP].pdst],key=str)) 
                else:
                    sess = p.sprintf("Ethernet type=%04xr,Ether.type%")
            return sess
        try:
            pcap_for_analysis
            # No args for the summary
            if len(args) == 0:           
                duplex_sessions = len(pcap_for_analysis.sessions(full_duplex))
                print "The total stateful connections in this pcap is " + str(duplex_sessions)
            # Arg 'all' for a list of all stateful connections    
            elif args == "all":
                stateful = pcap_for_analysis.sessions(full_duplex)
                for session in stateful:
                    print session
            # 'detailed' gives each connection, then the corresponding back and forth packets that comprise the 
            # connection
            elif args == "detailed":
                stateful = pcap_for_analysis.sessions(full_duplex)
                for k, v in stateful.iteritems():
                    print k
                    print v.summary()                  
            else:
                print args
                print "Invalid argument. Try 'help stateful' for options."
        except:
            print "You need to load a pcap first. Try 'help load'"

     
            
##############################################################################################
# HTTP Stuff
##############################################################################################   
    #############################################################
    # Extract http headers where connection type is GET
    ############################################################# 
    def do_httpget(self, args):
        """Extract http GET headers from the pcap"""
        http_get_list = []
        try:
            pcap_for_analysis
            if len(args) == 0:        
                for packet_number in range(pcap_len):
                    packet = pcap_for_analysis[packet_number]
                    try: 
                        # Check if it's a TCP packet
                        packet.haslayer(TCP)
                        # Pull out the payload
                        packet_payload = str(packet[3])
                        # If the word user appears in the payload, convert to list
                        if "GET " in packet_payload:
                            # print packet.sprintf("{Raw:%Raw.load%}").split(r"\r\n")
                            print '############################################'
                            print '# Packet Number:'
                            print '############################################'
                            print packet_number                          
                            print '############################################'
                            print '# Packet Summary:'
                            print '############################################'
                            print packet.summary()
                            print '############################################'
                            print '# HTTP GET Header:'
                            print '############################################'                            
                            print str(packet[3])
                    except:
                        pass
            else:
                print 'No arguments needed.'

        except:
            print "You need to load a pcap first. Try 'help load'"
 
    #############################################################
    # Extract http headers where connection type is POST
    ############################################################# 
    def do_httppost(self, args):
        """Extract http POST headers from the pcap"""
        http_get_list = []
        try:
            pcap_for_analysis
            if len(args) == 0:        
                for packet_number in range(pcap_len):
                    packet = pcap_for_analysis[packet_number]
                    try: 
                        # Check if it's a TCP packet
                        packet.haslayer(TCP)
                        # Pull out the payload
                        packet_payload = str(packet[3])
                        # If the word user appears in the payload, convert to list
                        if "POST " in packet_payload:
                            # print packet.sprintf("{Raw:%Raw.load%}").split(r"\r\n")
                            print '############################################'
                            print '# Packet Number:'
                            print '############################################'
                            print packet_number                               
                            print '############################################'
                            print '# Packet Summary:'
                            print '############################################'
                            print packet.summary()
                            print '############################################'
                            print '# HTTP POST Header:'
                            print '############################################'                            
                            print str(packet[3])
                    except:
                        pass
            else:
                print 'No arguments needed.'

        except:
            print "You need to load a pcap first. Try 'help load'"    
    
    
    #############################################################
    # Extract unqiue user agents:
    ############################################################# 
    def do_uaunique(self, args):
        """Extract unique user agents from the pcap"""
        ua_list =[] 
        try:
            pcap_for_analysis
            if len(args) == 0:        
                for packet_number in range(pcap_len):
                    packet = pcap_for_analysis[packet_number]
                    try: 
                        # Check if it's a TCP packet
                        packet.haslayer(TCP)
                        # Pull out the payload
                        packet_payload = str(packet[3])
                        # If the word user appears in the payload, convert to list
                        if "User-Agent" in packet_payload:
                            # This converts it to a list: 
                            packet_list = packet.sprintf("{Raw:%Raw.load%}").split(r"\r\n")
                            # Append each UA to the list: 
                            for i in packet_list:
                                if 'User-Agent' in i:
                                    ua_list.append(i)
                    except:
                        pass
                for ua in set(ua_list):
                    print ua
        except:
            print "You need to load a pcap first. Try 'help load'"


    #############################################################
    # Extract all user agents:
    ############################################################# 
    def do_uaall(self, args):
        """Extract all user agents from the pcap. Results are returned in the format: packet number,timestamp,user agent,destination IP"""
        ua_list =[] 
        try:
            pcap_for_analysis
            if len(args) == 0:        
                for packet_number in range(pcap_len):
                    packet = pcap_for_analysis[packet_number]
                    try: 
                        # Check if it's a TCP packet
                        packet.haslayer(TCP)
                        # Pull out the payload
                        packet_payload = str(packet[3])
                        # If the word user appears in the payload, convert to list
                        if "User-Agent" in packet_payload:
                            # This converts it to a list: 
                            packet_list = packet.sprintf("{Raw:%Raw.load%}").split(r"\r\n")
                            # Append each UA to the list: 
                            for i in packet_list:
                                if 'User-Agent' in i:
                                    relevant_data = str(packet_number) + ',' + str(packet.time) + ',' + i + ',' + packet[IP].dst
                                    ua_list.append(relevant_data)
                    except:
                        pass
                for ua in ua_list:
                    print ua
        except:
            print "You need to load a pcap first. Try 'help load'"

    
##############################################################################################
# DNS Stuff
##############################################################################################   
    #############################################################
    # Show all dns queries in the pcap:
    #############################################################
    def do_dnsall(self, args):
        """Extract all DNS Queries from the pcap.Results are shown in the format: packet number,timestamp,query_name"""
        try:
            pcap_for_analysis
            if len(args) == 0:
                print 'Extracting all dns queries now....'
                query_list = ''
                for packet_number in range(pcap_len):
                    packet = pcap_for_analysis[packet_number]
                    try:
                        if packet[UDP].dport == 53:
                            query_list += str(packet_number) + ',' + str(packet.time) + ',' + str(packet[DNSQR].qname) + '\n'
                    except:
                        pass
                print query_list
            else:
                print 'No args needed if you loaded a pcap.'    
        except:
            print "You need to load a pcap first. Try 'help load'"
    
    #############################################################
    # Show unique dns queries in the pcap:
    #############################################################    
    
    def do_dnsunique(self, args):
        """Extract all DNS Queries from the pcap"""
        global pcap_for_analysis
        if len(args) == 0:
            print 'Extracting unique dns queries now....'
            query_list = []
            for packet in pcap_for_analysis:
                try:
                    if packet[UDP].dport == 53:
                        query_list.append(packet[DNSQR].qname)
                except:
                    pass
            for query in set(query_list):
                print query
        else:
            print 'No args needed if you loaded a pcap.'      
    
if __name__ == '__main__':
        console = Console()
        console . cmdloop() 
