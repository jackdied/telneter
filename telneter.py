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

val_to_name = {}
for k, v in locals().items():
    try:
        if 0 <= ord(v) <= 255:
            val_to_name[v] = k
    except (ValueError, TypeError):
        pass
val_to_name[ECHO] = 'ECHO'  # TODO, double check 'SEND' == 0x01

def clean_data(data):
    """ the old telnetlib does this, I'm not sure why """
    return data.replace(chr(0),'').replace('\021', '')


# TODO: rename IAC_escape to plain escape()?
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
  
    text, rest = partition_control(data)
    if text:
        # in 99.9999% of cases this is pure text and 'rest' will be empty
        return None, text, rest

    control, unparsed = parse_control(rest)
    return control, b'', unparsed


def partition_control(data):
    ''' split data into <text>, and <rest> where <rest> is possibly a control sequence '''

    # cool story: in CPython if the string to be replaced doesn't exist then
    # it skips the copy. So don't manually do our own find(IAC) here.

    # search with the IACIACs removed
    plain = data.replace(IAC+IAC, ':)')
    iac_i = plain.find(IAC)
    if iac_i == -1:
        return data.replace(IAC+IAC, IAC), b''

    return data[:iac_i], data[iac_i:]


def parse_control(data):
    ''' data must start with an IAC sequence.
        return ((cmd, option, sb_data), unparsed_data)
    '''
    assert data[0] == IAC
    # okie, we have an IAC at position zero.  do some work.
    # we index blindly through the array, if we get an IndexError we have
    # a partial IAC sequence, just return and we'll try it again when we have more data
    try:
        cmd = data[1]
        option = data[2]
    except IndexError: 
        # we didn't have the full IAC sequence, try again later
        return None, data

    if cmd != SB:
        unparsed = data[3:]
        return (cmd, option, b''), unparsed

    # search with the IACIACs removed
    plain = data.replace(IAC+IAC, ':)')
    i = plain.find(IAC+SE)
    if i == -1:
        # no terminator, try again later
        return None, data

    # IAC SB OPTION <data> IAC SE
    sb_data = data[3:i]
    sb_data = sb_data.replace(IAC+IAC, IAC)
    unparsed = data[i+2:]
    return (cmd, option, sb_data), unparsed


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

    def __repr__(self):
        return '<%s at %d state=%r>' % (self.__class__.__name__,
                                        id(self),
                                        {val_to_name[opt]: val_to_name[v] for opt, v in self.options.items()})


class TelnetStream(object):
    ''' I/O interface for a Telnet Stream '''
    def __init__(self, state=None):
        if state is None:
            state = TelnetState.make_smartstate()
        self.state = state
        self.unparsed_data = b''
        self.pending_outputs = []

    def receive_data(self, data):
        ''' Consume data. May cause new pending outputs to be generated. '''
        self.unparsed_data += data
        control, text, unparsed = parse(self.unparsed_data)
        self.unparsed_data = unparsed

        # only one of these happens per parse()
        if control:
            response = self.recieve_command(*control)
        elif text:
            response = self.recieve_text(text)
        if response:
            self.pending_outputs.append(response)
        return

    def recieve_command(self, cmd, option, sb_data):
        return self.tstate(recieve_command(cmd, option, sb_data))

    def recieve_text(self, data):
        pass


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
