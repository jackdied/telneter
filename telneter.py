''' Parse telnet streams and keep telnet session state '''

import re
import find_IACSE
# import some telnet negotiation constants
from telnetlib import IAC, DONT, DO, WONT, WILL, SE, NOP, GA, SGA, SB, ECHO, EOR, AYT, NAWS, TTYPE, STATUS
TELOPT_EOR = chr(239)
# a couple standard ones used in TTYPE
SEND = chr(1)
IS = chr(0)
# and define some non-official ones
MCCP2 = chr(86)  # Mud Compression Protocol, v2
MCCP1 = chr(85)  # Mud Compression Protocol, v1 (broken and not supported here)
MSP = chr(90) # Mud Sound Protocol
MXP = chr(91) # Mud eXtension Protocol

val_to_name = {IAC:'IAC',DONT:'DONT',DO:'DO',WILL:'WILL',WONT:'WONT',SE:'SE',NOP:'NOP',GA:'GA',SB:'SB',ECHO:'ECHO',EOR:'EOR',
               MCCP2:'MCCP2', MCCP1:'MCCP1', AYT:'AYT', NAWS:'NAWS', TTYPE:'TTYPE', MSP:'MSP', MXP:'MXP',TELOPT_EOR:'TELOPT_EOR'}

# TODO: rename IAC_escape to plain escape()?

def clean_data(data):
    """ the old telnetlib does this, I'm not sure why """
    return data.replace(chr(0),'').replace('\021', '')

def IAC_escape(data):
    """ double up any IACs in the string """
    return data.replace(IAC, IAC+IAC)

def construct_control(cmd, option=b'', sb_data=b''):
    if cmd != SB:
        if sb_data:
            raise ValueError("Don't know how to construct an %r command with a payload" % cmd)
        return IAC + cmd + option
    return IAC + SB + option + IAC_escape(sb_data) + IAC + SE

def parse(data):
    '''
    Parse the data and return a three tuple of the control stream, pure text data, and unparsed data.
    *Only one* of control stream or text data will be returned.
    Unparsed data may always be returned.
    The control stream is returned as None or a three tuple of bytestrings (cmd, option, sb_data).
    '''
  
    if not data:
        return None, b'', b''

    iac_ind = data.find(IAC)
    if iac_ind == -1:  # typical case, no telnet negotiation
        return None, data, b''

    # IAC hiding in there
    if iac_ind:  # not at zero, return the data first
        text_data = data[:iac_ind]
        unparsed = data[iac_ind:]
        return None, text_data, unparsed

    # okie, we have an IAC at position zero.  do some work.
    # we index blindly through the array, if we get an IndexError we have
    # a partial IAC sequence, just return and we'll try it again when we have more data
    try:
        cmd = data[1]
        i = 2 # just after the command
        if cmd == IAC:  # escaped IAC
            unparsed = data[i:]
            return None, IAC, unparsed
        elif cmd != SB:
            option = data[i]
            unparsed = data[i+1:]
            return (cmd, option, b''), b'', unparsed
        else:
            # parse the SB payload
            option = data[i]
            i += 1
            i = first_unescaped_IACSE(data)
            sb_data = data[3:i] # IAC SB OPTION <data> IAC SE
            sb_data = sb_data.replace(IAC+IAC, IAC)  # fixup escaped IACs, if any
            unparsed = data[i+2:]
            return (cmd, option, sb_data), b'', unparsed
    except IndexError: 
        # we didn't have the full IAC sequence, try again later
        return None, b'', data

    raise RuntimeError("Unreachable")

def first_unescaped_IACSE(haystack):
    ''' find the first IAC+SE in haystack
        while being mindful that IAC+IAC means an escaped IAC
    '''
    # use the simple & fast (in the usual case) version that doesn't do an in memory copy.
    return find_IACSE.find_simple3(haystack)

# [1] RFC 855
# if parameters in an option "subnegotiation" include a byte
# with a value of IAC, it is necessary to double this byte in
# accordance the general TELNET rules.

matching_willdo_pairs = [
    (WILL, DO),
    (WONT, DONT),
    (DO, WILL),
    (DONT, WONT),
]

def dont_wont(tstate, cmd, option, sb_data):
    ''' reply to any request with NOPE NOPE NOPE '''
    if option is None:
        tstate.bad_commands.append((cmd, option, sb_data))
        return b''  # no option, so we don't know what to refuse to do
    if cmd in [WILL, WONT]:
        tstate.options[option] = DONT
        return IAC + DONT + option
    if cmd in [DO, DONT]:
        tstate.options[option] = WONT
        return IAC + WONT + option

class TelnetState(object):
    ''' State of negotiated options for the session and registry for nego handlers '''

    def __init__(self):
        self.handlers = {'default': dont_wont}
        # state of current negotated options
        self.options = {}
        # record all cmd request tuples and byte responses
        self.history = []
        # remember if we have ever seen the other end do *real* negotiation
        self.can_negotiate = False
        # record slightly invalid command tuples
        self.bad_commands = []
    
    @classmethod
    def make_smartstate(cls):
        ''' return a new TelnetState object with some enhanced sensible handlers '''
        tstate = cls()
        tstate.handlers[AYT] = AYT_handler
        tstate.handlers[ECHO] = ECHO_handler
        return tstate

    @property
    def local_echo(self):
        ''' return True if we are echoing, False otherwise '''
        # if we told the server DO ECHO then we shouldn't echo locally
        return self.options.get(ECHO) != DO

    def recieve_command(self, cmd, option, sb_data):
        ''' check our handlers and construct a reply as well as updating our state '''
        if option in self.handlers:
            handler = self.handlers[option]
        elif cmd in self.handlers:
            handler = self.handlers[cmd]
        elif 'default' in self.handlers:
            handler = self.handlers['default']
        else:
            self.history.append(b'')
            return b''

        if option not in [None, ECHO]:
            self.can_negotiate = True  # not just a dumb server

        # RFC 854 says we should ignore a request if we are already in the desired state
        current = self.options.get(option)
        for ask, result in matching_willdo_pairs:
            if cmd == ask and current == result:
                return b''

        response = handler(self, cmd, option, sb_data)
        self.history.append(response)
        return response

    def construct_status(self):
        ''' return a bytestring command sequence that says what we think the world looks like '''
        payload = b''
        for option, status in sorted(self.options.items()):
            payload += status + option  # e.g. WILL+ECHO
        return construct_control(SB, STATUS+IS, payload)


def AYT_handler(tstate, cmd, option, sb_data):
    ''' Are You There:
        provides the user with some visible (e.g., printable) evidence that the system is still up and running.
    '''
    if option or sb_data:
        tstate.bad_commands((cmd, option, sb_data))
    return b'I Am Here'

def ECHO_handler(tstate, cmd, option, sb_data):
    if sb_data:
        tstate.bad_commands((cmd, option, sb_data))
    if cmd == WILL:
        # prefered, the server will echo our commands back to us
        tstate.options[ECHO] = DO
        return IAC + DO + ECHO
    if cmd == WONT:
        tstate.options[ECHO] = DONT
        return IAC + DONT + ECHO
        
