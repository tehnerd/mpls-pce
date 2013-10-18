import struct
from string import join

class PCEP(object):
    """
6.1. Common Header


     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Ver |  Flags  |  Message-Type |       Message-Length          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                Figure 7: PCEP Message Common Header
   Ver (Version - 3 bits):  PCEP version number.  Current version is
      version 1.

   Flags (5 bits):  No flags are currently defined.  Unassigned bits are
      considered as reserved.  They MUST be set to zero on transmission
      and MUST be ignored on receipt.

   Message-Type (8 bits):  The following message types are currently
      defined:

         Value    Meaning
           1        Open
           2        Keepalive
           3        Path Computation Request
           4        Path Computation Reply
           5        Notification
           6        Error
           7        Close

   Message-Length (16 bits):  total length of the PCEP message including
      the common header, expressed in bytes.

    ...
   A PCEP object carried within a PCEP message consists of one or more
   32-bit words with a common header that has the following format:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Object-Class  |   OT  |Res|P|I|   Object Length (bytes)       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   //                        (Object body)                        //
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    def __init__(self):
        self._common_hdr_fmt="!BBH"
        self._common_obj_hdr_fmt="!BBH"
        self._open_obj_fmt="!BBBB"
        self._error_obj_fmt="!BBBB"
        """ TLV Stateful PCE Capability: Update Capability 1, Include DB version: 0"""
        self._spc_tlv = struct.pack('!HHI',16,4,1)
        self._state = 'not_initialized'
    
    def parse_rcved_msg(self,msg):
        common_hdr = struct.unpack(self._common_hdr_fmt,msg[0:4])
        print(common_hdr)
        if common_hdr[1] == 1:
            print('open msg recved')
            self.parse_open_msg(common_hdr, msg)
        elif common_hdr[1] == 2:
            print('ka msg recved')
            self.parse_ka_msg(common_hdr, msg)
        elif common_hdr[1] == 3:
            print('pcreq msg recved')
        elif common_hdr[1] == 4:
            print('pcrep msg recved')
        elif common_hdr[1] == 5:
            print('ntf msg recved')
        elif common_hdr[1] == 6:
            print('error msg recved')
            self.parse_error_msg(common_hdr,msg)
        elif common_hdr[1] == 7:
            print('close msg recved')
        """ draft-ietf-pce-stateful-pce extensions """

    """
   The format of the OPEN object body is as follows:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Ver |   Flags |   Keepalive   |  DeadTimer    |      SID      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   //                       Optional TLVs                         //
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                    Figure 9: OPEN Object Format

    """

    def parse_open_msg(self,common_hdr, msg):
        open_msg = struct.unpack_from(self._open_obj_fmt,msg[8:])
        print(struct.unpack_from(self._common_obj_hdr_fmt,msg[4:]))
        self._peer_ka_timer = open_msg[1]
        self._test_openmsg = msg
        if(common_hdr[2] > 12):
            print(struct.unpack_from('!HHI',msg[12:]))
        self._state = 'initialized'
        print(open_msg)

    def parse_error_msg(self,common_hdr, msg):
        print(struct.unpack_from(self._common_obj_hdr_fmt,msg[4:]))
        error_msg = struct.unpack_from(self._error_obj_fmt,msg[8:])
        print(error_msg)
    
    def generate_open_msg(self,ka_timer):
        self._ka_timer = ka_timer
        common_hdr = struct.pack(self._common_hdr_fmt,32,1,20)
        common_obj_hdr = struct.pack(self._common_obj_hdr_fmt,1,16,16)
        open_obj = struct.pack(self._open_obj_fmt,32,ka_timer,ka_timer*4,32)
        return join((common_hdr,common_obj_hdr,open_obj,self._spc_tlv),sep='')

    def generate_ka_msg(self):
        common_hdr = struct.pack(self._common_hdr_fmt,32,2,4)
        return common_hdr

    def parse_ka_msg(self,common_hdr,msg):
        pass
        
        
