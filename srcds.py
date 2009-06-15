#!/usr/bin/env python
#SRCDS.py
#Half-Life 2 and Half-Life Dedicated Server Interface for Python
#Released under the LGPL (http://www.gnu.org/licenses/lgpl.html)
#
#Based off (most code copied from) SRCDS.py by Sean C. Steeg
#

__author__ = 'faux@fauxsoft.com'
__license__ = 'http://www.gnu.org/licenses/lgpl.html'
__date__ = '08 June 2009'
__version__ = 'faux_1.1.07'
__credits__ = """Christopher Munn for SRCDS.py 2.02.
                 Sean C. Steeg for SRCDS.py 1.01.
                 Bryan Gerber, for the original HLDS.py.
                 The players and staff of TacticalGamer.com, who make us want to do stuff like this.
              """

import socket, re, xdrlib, string, sys, os
import time
from optparse import OptionParser

#Server Query Constants
DETAILS = "TSource Engine Query\x00"
DETAILS_RESP_HL2 = 'I'
DETAILS_RESP_HL1 = 'm'
GETCHALLENGE = 'W'
CHALLENGE = 'A'
PLAYERS = 'U'
PLAYERS_RESP = 'D'
RULES = 'V'
RULES_RESP = 'E'
PING = 'i'
PING_RESP = 'j'
SERVER_ERROR = 'l'
#HL2 RCON Constants
SERVERDATA_RESPONSE_VALUE = 0
SERVERDATA_AUTH_RESPONSE = 2
SERVERDATA_EXECCOMMAND = 2
SERVERDATA_AUTH = 3
RCON_EMPTY_RESP = (10,0,0,'','')
#HL1 RCON Constants
RCON_CHALLENGE = "challenge rcon\n"

#Default port to connect to
SRCDS_DEFAULT_PORT = 27015

##################################################
# Network data manipulation
def hldsunpack_int(data):
    """
Network traffic is big endian, and xdrlib wants little endian, meaning the
bytes need to be reversed in order for xdrlib to work its magic."""
    s = ""
    for c in data:
        s = c + s
    p = xdrlib.Unpacker(s)
    return p.unpack_int()

def hldsunpack_float(data):
    """
Network traffic is big endian, and xdrlib wants little endian, meaning the
bytes need to be reversed in order for xdrlib to work its magic."""
    s = ""
    for c in data:
        s = c + s
    p = xdrlib.Unpacker(s)
    return p.unpack_float()

def hldspack_int(integer):
    s = ""
    p = xdrlib.Packer()
    p.pack_int(integer)
    data = p.get_buffer()
    for c in data:
        s = c + s
    return s

##################################################
# Functions for reading packets 
def read_byte(data):
    return (ord(data[0]), data[1:])

def read_char(data):
    return (str(data[0]), data[1:])

def read_string(data):
    s = ''
    i = 0
    while 1:
        if str(data[i]) != '\x00':
            s = s + str(data[i])
            i += 1
        else:
            break
    return (s, data[i+1:])

def read_int(data):
    ret = hldsunpack_int(data[0:4])
    return (ret, data[4:])

def read_float(data):
    ret = hldsunpack_float(data[0:4])
    return (ret, data[4:])

def read_short(data):
    aid1, data = read_byte(data)
    aid2, data = read_byte(data)
    return ((aid2 * 0x100) + aid1, data)
    
    
##################################################
# Exceptions
class SRCDS_Error(Exception):
    """Base error."""
    pass

class RCON_Error(Exception):
    """Raised when a command requiring RCON is given, but the RCON password is missing or incorrect."""
    pass

##################################################
# SRCDS class
class SRCDS:
    """
HL2DS/HLDS Interface class. Supports HL2 and HL servers.

Initialization: OBJ = SRCDS(host, [port=27015], [rconpass=''], [timeout=2.0])
Note: timeout is in seconds. host may be ip or hostname
    """

    def __init__(self, host, port=27015, rconpass='', timeout=10.0):
        self.host = host
        self.ip, self.port, self.rconpass, self.timeout = socket.gethostbyname(host), port, rconpass, timeout
        self.udpsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.tcpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.udpsock.settimeout(self.timeout)
        self.tcpsock.settimeout(self.timeout)
        self.udpsock.connect((self.ip, self.port))
        self.challenge, self.rcon_challenege, self.req_id, self.hl = -1, 0, 0, 0
        if self.rconpass: 
            self._authenticate_rcon()

    ##################################################
    # RCON Packet functions
    def send_packet(self, command, string1, string2=''):
        """Crafts and sends a packet to the server."""
        #Increment self.req_id, so all commands have unique id
        self.req_id += 1
        #Make the packet from the end going backwards
        packet = string1 + '\x00' + string2 + '\x00'
        #Add command
        packet = hldspack_int(command) + packet
        #Add request_id
        packet = hldspack_int(self.req_id) + packet
        #Add an int of the packet length
        packet = hldspack_int(len(packet)) + packet
        #Send packet to server
        self.tcpsock.send(packet)
        #Return req_id of packet
        return self.req_id
        
    def read_packet(self):
        """Parses a single response packet from the server."""
        raw_packetlen = self.tcpsock.recv(4)
        packetlen = hldsunpack_int(raw_packetlen)
        raw_packet = self.tcpsock.recv(packetlen)
        req_id = hldsunpack_int(raw_packet[0:4])
        command = hldsunpack_int(raw_packet[4:8])
        raw_packet = str(raw_packet[8:])
        if len(raw_packet) == 2:
            strs = ['', '']
        else:
            strs = re.split('[\000]', raw_packet[:-1], 1)
        return (packetlen, req_id, command, strs[0], strs[1])    
    
    def _authenticate_rcon(self):
        if not self.rconpass: raise RCON_Error, 'Empty RCON password.'
        if self.hl == 0:
            self.details()
        if self.hl == 1:
            self._authenticate_rcon_hl1()
        else:
            self._authenticate_rcon_hl2()

    def _authenticate_rcon_hl1(self):
        self.rcon_challenge =  self._any_response(RCON_CHALLENGE)[15:-2]
        response = self._any_rcon_response_hl1('say')
        if response == 'Bad rcon_password.':
            raise RCON_Error, 'Invalid RCON password.'
        
    def _authenticate_rcon_hl2(self):
        self.tcpsock.connect((self.ip, self.port))
        req_id = self.send_packet(SERVERDATA_AUTH, self.rconpass, '')
        i = 0
        result = RCON_EMPTY_RESP
        while result != (10,req_id,SERVERDATA_AUTH_RESPONSE,'',''):
            result = self.read_packet()
            if result[1] == -1:
                raise RCON_Error, 'Invalid RCON password.'

    def _any_rcon_response(self, command):
        """
This function returns the raw response for commands requiring RCON.
No parsing is done by this function.
        """
        if self.hl == 1:
            return self._any_rcon_response_hl1(command)
        else:
            return self._any_rcon_response_hl2(command)[3]
    
    def _any_rcon_response_hl1(self, command):
        query = "rcon " + self.rcon_challenge + ' "' + self.rconpass + '" ' + command
        return self._any_response(query)[1:]

    def _any_rcon_response_hl2(self, command):
        req_id = self.send_packet(SERVERDATA_EXECCOMMAND, command)
        result = RCON_EMPTY_RESP
        while result[1] != req_id:
            result = self.read_packet()
        return result                

    ##################################################
    # RCON functions
    def set_rconpass(self, password):
        '''
        sets the rcon password after-the-fact, in case you did not specify 
        this in the constructor.
        '''
        self.rconpass = password
        self._authenticate_rcon()
        
    def rcon_command(self, command):
        '''
        executes any rcon command on the server.
        '''
        return self._any_rcon_response(command)

    def changelevel(self, map):
        '''
        changes the map.
        '''
        self._any_rcon_response('changelevel %s' %map)

    def ban(self,steamid,length=0):
        """
        Bans a user with a given steamid; length given in minutes
        """
        self.rcon_command("banid %d %s" % (length,steamid)) 
        self.rcon_command("writeid") 

       
    def unban(self,steamid):
        """
        Unbans a user with a given steamid.
        """
        self.rcon_command("removeid %s" % steamid) 
        self.rcon_command("writeid") 

    def say(self, statement):
        '''
        cause the console to say something in-game to the players.
        '''
        self._any_rcon_response('say %s' %statement)

    def quit(self):
        '''
        quits the server.
        '''
        self._any_rcon_response('quit')

    def restart(self):
        '''
        restarts the server.
        '''
        self._any_rcon_response('_restart')

    def version(self):
        '''
        returns the version information for the host srcds server.
        '''
        d = self.status()
        return d['version']

    def currentmap(self):
        '''
        returns the current map that the server is running.
        '''
        d = self.status()
        return d['map']

    def nplayers(self):
        '''
        returns the number of players present on the server.
        '''
        d = self.status()
        return d['players']

    def cvar(self, var):
        '''
        returns the value of any public console variable.
        '''
        raw_status = self._any_rcon_response(var)
        val = re.match('^"(.*?)" = "(.*?)"', raw_status)
        if val:
            return val.group(2)
        else:
            return None


    def status(self):
        '''
        returns two dictionaries: info, and player.
        the info dictionary contains: map, version, players, slots, name, ip, port, fps, cpu_usage, in, out, users
        player is a dictionary of dictionaries, keyed by the user id.  Each dictionary is the status info on a player.
        '''
        raw_status = self._any_rcon_response('status')
        raw_stats = self._any_rcon_response('stats')
        info = {} 
        lines = re.split("\n",raw_status)
        line = lines.pop(0)
        while (line == '' or line[0] != '#') and len(lines) != 0:
            parts = line.split(":")
            kw = parts[0].strip()
            if kw == "version":
                info['version'] = parts[1].strip()
            elif kw == "map":
                info['map'] = parts[1].split()[0]
            elif kw == "udp/ip":
                info['ip'] = parts[1].strip()
                info['port'] = parts[2].strip()
            elif kw == "hostname":
                info['name'] = parts[1].strip()
            elif kw == "players":
                #players :  17 (24 max)
                t = parts[1].split('(')
                info['players']   = int(t[0])
                info['slots'] = int(t[1].split()[0])
            line = lines.pop(0)
        keys = re.split(' +', line)
        keys.pop(0)
        if self.hl == 1:
            temp = keys[0]
            keys[0] = keys[1]
            keys[1] = temp
        players = {}
        for line in lines:
            if line and line[0] == '#':
                line = re.split('"', line, 3)
                id = int(re.split(' +', line[0])[1])
                players[id] = {}
                players[id] [keys[1]] = line[1]
                values = re.split(" +", line[2])
                if self.hl == 1:
                    values.pop(0)
                for i, key in enumerate(keys[2:]):
                   players[id][key] = values[i+1]

        # now that we are finishing parsing through the status output, parse through
        # the stats output.
        lines = raw_stats.split('\n')
        items = lines[1].split() 
        info['cpu_usage'] = items[0]
        info['in']        = items[1]
        info['out']       = items[2]
        info['uptime']    = items[3]
        info['users']     = items[4]
        info['fps']       = items[5]

        # finally, add whatever is in the details dictionary to our info dictionary.
        d = self.details()
        for k,v in d.iteritems(): info[k] = v

        return (info,players)

    def _recv_splitpacket(self, data=None):
        """receives and parses split packet"""
        if not data:
            data = self.udpsock.recv(4096)
        packet = {}
        #this header differs based on the server we are querying.
        #the datatypes differ if it is a goldsource/source server
        #for simplicity we are going to just do source first
        #then in the future fix goldsource servers
        packet['type'], data = read_int(data)
        packet['request_id'], data = read_int(data)

        #goldsource packet info
        packet['gs_packet_num'], discard = read_byte(data)
        packet['gs_packet_index'] = (packet['gs_packet_num'] & 0xF0) >> 4
        packet['gs_packet_count'] = packet['gs_packet_num'] & 0x0F

        packet['s_packet_num'], data = read_short(data)
        packet['index'] = (packet['s_packet_num'] & 0xFF00) >> 8
        packet['count'] = packet['s_packet_num'] & 0x00FF

        packet['split_size'], data = read_short(data)
        packet['data'] = data

        return packet

    ##################################################
    # Query packet functions
    def _any_response(self, query, raw=False):
        """
This assembles mult-packet responses and returns the raw response (sans the four \xFF's).  No parsing is done by this function.
raw=True:   This will return a tuple (data, raw_data) where raw_data is the raw response (WITH the four \xFF's).
"""
        self.udpsock.send('\xFF\xFF\xFF\xFF' + query)
        raw_data = self.udpsock.recv(4096)
        type, data = read_int(raw_data)
        #the data is split. it gets a bit hairy here.
        if type == -2:
            #TODO:  We are ignoring two parts of the spec here.
            #       Mostly because I haven't run into this yet.
            #   1:  Incoming packets should be grouped by request_id.
            #       This would cause a problem in an instance
            #       where we had more than one request coming
            #       in at a time.
            #
            #   2:  The source engine can bzip2 packets before
            #       they are split. This needs to be taken into
            #       account. 
            packet = self._recv_splitpacket(raw_data)
            buffer = [packet]
            buffer_size = packet['count']
            while len(buffer) < buffer_size:
                packet = self._recv_splitpacket()
                buffer.append(packet)

            #sort packets by index 
            buffer.sort(lambda x, y: cmp(x['index'], y['index']))
            #rejoin the packet
            data = ''.join([packet['data'] for packet in buffer])
            #strip off the type
            type, data = read_int(data)
        if data[0] == SERVER_ERROR:
            err, data = read_byte(data)
            err_message,data = read_string(data)
            raise SRCDS_Error, "Server error: %s" % err_message
        return data if not raw else (data,raw_data)
        
    ##################################################
    # Queries
    def getchallenge(self):
        raw_challenge = self._any_response(GETCHALLENGE)
        if raw_challenge[0] != CHALLENGE: 
            raise SRCDS_Error, 'GetChallenge Query Error: Unknown response type'
        data = raw_challenge[1:]
        self.challenge, data = read_int(data)
        return self.challenge

    def ping(self):
        t = time.time()
        raw_ping, raw_packet = self._any_response(PING, raw=True)
        if raw_ping[0] == PING_RESP:
            t = (time.time() - t) * 1000
            ping_resp = {'time': t}
            packet_type, data = (read_byte(raw_ping))
            ping_resp['type'] = chr(packet_type)
            ping_resp['content'], data = read_string(data)
            ping_resp['size'] = len(raw_packet)
            return ping_resp
        else:
            raise SRCDS_Error, 'Ping Error: Unknown response type %s' % repr(raw_ping)
    
    def details(self):
        raw_details = self._any_response(DETAILS)
        if raw_details[0] == DETAILS_RESP_HL2:
            self.hl = 2
            return self._details_hl2(raw_details[1:])
        elif raw_details[0] == DETAILS_RESP_HL1:
            self.hl = 1
            return self._details_hl1(raw_details[1:])
        else:
            raise SRCDS_Error, 'Detail Query Error: Unknown response type'
    
    
    def _details_hl2(self, data):
        detaildict = {}
        detaildict['hl_version'] = 2
        detaildict['protocol_version'], data = read_byte(data)
        detaildict['server_name'], data = read_string(data)
        detaildict['current_map'], data = read_string(data)
        detaildict['game_directory'], data = read_string(data)
        detaildict['game_description'], data = read_string(data)
        detaildict['app_id'], data = read_short(data)
        detaildict['current_playercount'], data = read_byte(data)
        detaildict['max_players'], data = read_byte(data)
        detaildict['current_botcount'], data = read_byte(data)
        ded, data = read_char(data)
        if ded == 'd':
            detaildict['server_type'] = 'Dedicated'
        elif ded == 'p':
            detaildict['server_type'] = 'SourceTV'
        else:
            detaildict['server_type'] = 'Listen'
        os, data = read_char(data)
        if os == 'w':
            detaildict['server_os'] = 'Windows'
        else:
            detaildict['server_os'] = 'Linux'
        pworded, data = read_byte(data)
        detaildict['passworded'] = bool(int(pworded))
        secured, data = read_byte(data)
        detaildict['secure'] = bool(int(secured))
        detaildict['game_version'], data = read_string(data)
        # if there is data left over parse the Extra Data Flag (EDF)
        # if ( EDF & 0x80 )   short             The server's game port # is included
        # if ( EDF & 0x40 )   short string      The spectator port # and then the spectator server name are included
        # if ( EDF & 0x20 )   string            The game tag data string for the server is included [future use]
        if len(data) != 0:
            edf, data = read_byte(data)
            detaildict['edf'] = edf
            if edf & 0x80 != 0:
                detaildict['server_port'], data = read_short(data)
            if edf & 0x40 != 0:
                detaildict['spec_port'], data = read_short(data)
                detaildict['spec_name'], data = read_string(data)
            if edf & 0x20 != 0:
                detaildict['server_tags'], data = read_string(data)

        return detaildict

    def _details_hl1(self, data):
        detaildict = {}
        detaildict['hl_version'] = 1
        detaildict['game_ip'], data = read_string(data)
        detaildict['server_name'], data = read_string(data)
        detaildict['current_map'], data = read_string(data)
        detaildict['game_directory'], data = read_string(data)
        detaildict['game_description'], data = read_string(data)
        detaildict['current_playercount'], data = read_byte(data)
        detaildict['max_players'], data = read_byte(data)
        detaildict['protocol_version'], data = read_byte(data)
        ded, data = read_char(data)
        if ded == 'd':
            detaildict['server_type'] = 'Dedicated'
        else:
            detaildict['server_type'] = 'Listen'
        os, data = read_char(data)
        if os == 'w':
            detaildict['server_os'] = 'Windows'
        else:
            detaildict['server_os'] = 'Linux'
        pworded, data = read_byte(data)
        detaildict['passworded'] = bool(int(pworded))
        detaildict['ismod'], data = read_byte(data)
        if detaildict['ismod'] == 1:
            detaildict['mod_url_info'], data = read_string(data)
            detaildict['mod_url_dl'], data = read_string(data)
            detaildict['mod_unused'], data = read_string(data)
            detaildict['mod_version'], data = read_int(data)
            detaildict['mod_size'], data = read_int(data)
            mod_svonly, data = read_byte(data)
            detaildict['mod_svonly'] = bool(int(mod_svonly))
            mod_cldll, data = read_byte(data)
            detaildict['mod_cldll'] = bool(int(mod_cldll))
        secured, data = read_byte(data)
        detaildict['secure'] = bool(int(secured))
        detaildict['current_botcount'], data = read_byte(data)
        
        return detaildict
        
    def players(self):
        if self.challenge == -1:
            self.getchallenge()
        raw_players = self._any_response(PLAYERS + hldspack_int(self.challenge))
        if raw_players[0] != PLAYERS_RESP: raise SRCDS_Error, 'Player Query Error'
        data = raw_players[1:]
        playerlist = []
        playercount, data = read_byte(data)
        playercount = int(playercount)
        while len(data) != 0:
            currentplayer = {}
            cn, data = read_byte(data)
            currentplayer['index'] = int(cn)
            currentplayer['name'], data = read_string(data)
            currentplayer['frags'], data = read_int(data)
            currentplayer['time_on'], data = read_float(data)
            playerlist.append(currentplayer)
        return playerlist
        
    def rules(self):
        if self.challenge == -1:
            self.getchallenge()
        raw_rules = self._any_response(RULES + hldspack_int(self.challenge))
        if raw_rules[0] != RULES_RESP: raise SRCDS_Error, 'Rules Query Error'
        data = raw_rules[1:]
        rulescount, data = read_byte(data)
        rulescount = int(rulescount)
        nada, data = read_byte(data)    #placeholder to move up one byte
        ruleslist = string.split(str(data), '\x00')
        ruleslist.pop()
        rulesdict =  {}
        for everyother in ruleslist[::2]:
            rulesdict[everyother] = ruleslist[ruleslist.index(everyother) + 1]
        return rulesdict

    def disconnect(self):
        self.udpsock.close()
        
##################################################
# HLDS class (for backwards compatibility with HLDS.py)
class HLDS(SRCDS):
    def close(self):
        self.disconnect()

def split_hostport(address, default_port):
    """splits an address into HOST:PORT parts. default_port will be used if PORT is not a valid port."""
    addr = address.split(":")
    host = addr[0]
    # check the address and store the port if it exists and is a number
    if len(addr) > 1 and re.match("^\d+$", addr[1]):
        port = int(addr[1])
    else:
        port = default_port

    return host,port

def format_time(t):
    return ':'.join([str(x) for x in [t/3600, t/60 % 60, t % 60]])

def format_str(s, width=None, justify='left'):
    value = s
    if width == None:
        width = len(s)
    if justify == 'left':
        value = s + ' ' * (width - len(s))
    elif justify == 'right':
        value = ' ' * (width - len(s)) + s
    return value

def format_exception(e, process_name=True):

    process_name = os.path.basename(sys.argv[0]) + ": " if process_name else ''
    exception_message = str(e)
    exception_type = str(type(e)).split("'")[1]

    return ''.join([
            process_name,
            exception_type,
            ": ",
            exception_message
        ])

def ping_srcds(server, count=None, interval=1,
    print_response=None, # callbacks for printing
    print_exception=None,
):
    """Generic ping"""
    #capture start time
    start = time.time()
    #keep track of all packets we receive so roundtrip times can be calculated later
    packets = []
    try:
        #loop while until the count is exhausted
        while(count == None or count > 0):
            if count:
                count -= 1
            #ping and capture packet
            try:
                ping = server.ping()
            except Exception, exception:
                #capture the Exception
                packets.append(exception)
                if print_exception: print_exception(exception)
            else:
                packets.append(ping)
                if print_response: print_response(ping)
            time.sleep(interval)
    except KeyboardInterrupt:
        pass

    total_time = (time.time() - start) * 1000
    stats = {
        'packets': packets,
        'total_time': total_time
    }
    return stats

def srcds_ping(server, count=None, interval=1):
    def pr(response):
        print "%i bytes from %s:%s: type=%s content=%s time=%i ms" % (
            response['size'],
            server.ip,
            server.port,
            response['type'],
            response['content'],
            response['time'],
        )

    def pe(exception):
        print "%s:%s: %s" % (
            server.ip,
            server.port,
            format_exception(exception, process_name=False),
        )

    print "SRCDS_PING %s (%s) on port %s" % (server.host, server.ip, server.port)

    stats = ping_srcds(server, count, interval, print_response=pr, print_exception=pe)

    packets = stats['packets']
    print
    #responses are dictionaries with a time field
    responses = [resp for resp in packets if 'time' in resp]
    exceptions = [resp for resp in packets if isinstance(resp, Exception)]

    print "--- %s ping statistics ---" % server.ip
    print "%s packets transmitted, %s received, %s%% packet loss, time %i ms" % (
        len(packets),
        len(responses),
        len(exceptions)/len(packets) * 100,
        stats['total_time'],
    )
    if len(responses):
        times = [resp['time'] for resp in responses]
        print "rtt min/avg/max = %0.2f/%0.2f/%0.2f ms" % (
            min(times),
            sum(times)/len(times),
            max(times),
        )

    if count == None:
        sys.exit(0)

def display(obj):
    """displays python objects in a user-friendly manner. this means the printed result should be
       easily passed to grep/awk for further processing."""
    if isinstance(obj, dict):
        key_len = max([len(key) for key in obj])
        for key in obj:
            print key + ' ' * (key_len - len(key))+":", repr(obj[key])
        print
    elif isinstance(obj, list):
        if len(obj) == 0:
            return
        objs = obj
        mode = None
        collect = []
        defered = []
        for obj in objs:
            #keep track of type of objects we are printing. if they are of a differnt type, delay printing until later.
            if mode == None:
                mode = type(obj)
            elif mode != type(obj):
                defered.append(obj)
                continue

            collect.append(obj)

            if mode == dict:
                if not 'key_length' in locals().keys():
                    key_length = {}
                #find the default column size needed to display the keys
                for key in obj:
                    if not key in key_length:
                        key_length[key] = len(str(key)) 
                    length = len(repr(obj[key]))
                    if length > key_length[key]:
                        key_length[key] = length

        #we have to run through the list twice. this time we will print to the screen
        if mode == dict:
            for key in key_length:
                print format_str(key, key_length[key]),
            print

            for obj in collect:
                for key in key_length:
                    if key in obj:
                        value = repr(obj[key])
                    else:
                        value = ""
                    print format_str(value, key_length[key]),
                print
            print
        else:
            objs = [{'index': i, 'value': v} for i,v in enumerate(collect)]
            display(objs)

        display(defered)

if __name__ == "__main__":
    parser = OptionParser(usage="%prog host[:port] [command] [options]")
    parser.add_option("-P",dest="rcon_password",default="",help="Specifies the rcon password")
    parser.add_option("-t","--timeout",dest="timeout",type="int",default="10",help="Specifies the socket timeout")
    parser.add_option("-i","--interval",dest="interval",type="int",default="1",help="Specifies the interval between pings")
    parser.add_option("-n","--count",dest="count",type="int",help="Number of pings to send")
    (options,args) = parser.parse_args()

    options.ensure_value('port', 27015)
    options.ensure_value('rcon', "")
    options.ensure_value('timeout', 10)

    avail_commands = ['all', 'info', 'players', 'rules', 'ping', 'rcon']

    def show_usage():
        parser.parse_args(['-h'])

    command = []

    if len(args) == 0:
        show_usage()
    elif len(args) > 1:
        for arg in args:
            if arg in avail_commands:
                command.append(arg)
    else:
        command.append('info')

    host, port = split_hostport(args[0], SRCDS_DEFAULT_PORT)
    setattr(options, 'host', host)
    setattr(options, 'port', port)

    print "Connecting to %s:%s" % (options.host,options.port)
    s = SRCDS(options.host,options.port,rconpass=options.rcon_password,timeout=options.timeout)

    for cmd in command:
        if cmd == 'info':
            display(s.details())
        elif cmd == 'ping':
            srcds_ping(s, count=options.count, interval=options.interval)
        elif cmd == 'players':
            display(s.players())
        elif cmd == 'rules':
            display(s.rules())
        elif cmd == 'rcon':
            if len(options.rcon_password) == 0:
                raise SRCDS_Error, "Cannot use rcon without providing an rcon_password"
            print "using rcon_password '%s'" % ("*" * len(options.rcon_password))
            rcon_cmds = ' '.join(args[args.index('rcon')+1:]).split(';')

            for rcon_cmd in rcon_cmds:
                rcon_cmd = rcon_cmd.strip()
                print repr(rcon_cmd)
                print s.rcon_command(rcon_cmd)
