import struct
import socket
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

    draft-ietf-pce-stateful-pce:



   <PCRpt Message> ::= <Common Header>
                       <state-report-list>
Where:

   <state-report-list> ::= <state-report>[<state-report-list>]

   <state-report> ::= [<SRP>]
                      <LSP>
                      <path>
 Where:
   <path>::= <ERO><attribute-list>[<RRO>]

    """
    def __init__(self, open_sid = 0):
        self._common_hdr_fmt="!BBH"
        self._common_obj_hdr_fmt="!BBH"
        self._open_obj_fmt="!BBBB"
        self._error_obj_fmt="!BBBB"
        """ TLV Stateful PCE Capability: Update Capability 1, Include DB version: 0"""
        self._spc_tlv = struct.pack('!HHI',16,4,1)
        """
       SRP Object-Class is [TBD].
       SRP Object-Type is 1.
       The format of the SRP object body is shown in Figure 10:

              0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                          Flags                                |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                        SRP-ID-number                          |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      //                      Optional TLVs                          //
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        """
        self._srp_obj_fmt = "!II"
        self._rp_obj_fmt = "!II"
        self._nopath_obj_fmt = "!BHB"
        self._endpointsv4_obj_fmt = "!II"
        self._endpointsv6_obj_ftm = "!4I4I"
        self._bw_obj_fmt = "!I"
        self._metric_obj_fmt = "!HBBI"
        self._lspa_obj_fmt = "!IIIBBBB"
        self._lsp_obj_fmt = "!I"
        self._open_sid = open_sid % 255
        self._state = 'not_initialized'
        self._functions_dict = dict()
        self._functions_dict[4,1] = self.parse_endpoints_object
        self._functions_dict[5,1] = self.parse_bw_object
        self._functions_dict[5,2] = self.parse_bw_object
        self._functions_dict[6,1] = self.parse_metric_object
        self._functions_dict[7,1] = self.parse_ero_object
        self._functions_dict[8,1] = self.parse_rro_object
        self._functions_dict[9,1] = self.parse_lspa_object
        self._functions_dict[32,1] = self.parse_lsp_object

    def ip2int(self, addr):                                                               
        return struct.unpack_from("!I", socket.inet_aton(addr))[0]                       

    def int2ip(self, addr):                                                               
        return socket.inet_ntoa(struct.pack("!I", addr)) 
    
    def parse_rcved_msg(self, msg):
        common_hdr = struct.unpack(self._common_hdr_fmt,msg[0:4])
        print(common_hdr)
        if common_hdr[1] == 1:
            print('open msg recved')
            self.parse_open_msg(common_hdr, msg)
        elif common_hdr[1] == 2:
            print('ka msg recved')
            return self.parse_ka_msg(common_hdr, msg)
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
        elif common_hdr[1] == 10:
            print('pcc state report msg recved')
            return self.parse_state_report_msg(common_hdr,msg)
        elif common_hdr[1] == 11:
            print('pcc update msg recved')
        return ('NotImplemented',None) 

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
    In common object header:
    Object-Class is 1
    Object-Type is 1
    """


    def parse_open_msg(self,common_hdr, msg):
        self.parse_common_obj_hdr(msg)
        open_msg = struct.unpack_from(self._open_obj_fmt,msg[8:])
        self._peer_ka_timer = open_msg[1]
        self._test_openmsg = msg
        if(common_hdr[2] > 12):
            print(struct.unpack_from('!HHI',msg[12:]))
        self._state = 'initialized'
        print(open_msg)

    """
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Object-Class  |   OT  |Res|P|I|   Object Length (bytes)       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   //                        (Object body)                        //
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                  Figure 8: PCEP Common Object Header
    """

    def parse_common_obj_hdr(self,msg,offset=0):
        obj_hdr = struct.unpack_from(self._common_obj_hdr_fmt,msg[4+offset:])
        object_class = obj_hdr[0]
        object_type = obj_hdr[1]>>4
        object_length = obj_hdr[2]
        # 3 = 00000011
        PI_flags = obj_hdr[1]&3 
        print("obj header: oc:%s  ot:%s len:%s flags:%s"%(object_class,
                                                          object_type,
                                                          object_length,
                                                          PI_flags,))
        return (object_class, object_type, object_length, PI_flags)

        """
        request parameters object
        must be included in pcreq message
        RP Object-Class = 2
        RP Object-Type = 1
   The format of the RP object body is as follows:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          Flags                    |O|B|R| Pri |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Request-ID-number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   //                      Optional TLVs                          //
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                  Figure 10: RP Object Body Format
        4 - header size, 4 - common obj header size, thats why 8 + offset 
        """

    def parse_rp_object(self, msg, com_obj_hdr, offset=0):
        rp_object = struct.unpack_from(self._rp_obj_fmt,msg[8+offset:]) 
        rp_req_id = rp_object[1]
        rp_priority_flag = rp_object[0]&7
        rp_reopt_flag = rp_object[0]&8 
        rp_bidir_flag = rp_object[0]&16
        #strict/loose; 1 - loose is acceptable
        rp_o_flag = rp_object[0]&32
        return ('rp',(rp_req_id, rp_priority_flag, rp_reopt_flag, rp_bidir_flag,
                rp_o_flag))

        """
        used in pcreq
        v4 only atm, havent seen any v6 implementation, 
        so not even in TODO list.
        
   END-POINTS Object-Class is 4.

   END-POINTS Object-Type is 1 for IPv4 and 2 for IPv6.

   The format of the END-POINTS object body for IPv4 (Object-Type=1) is
   as follows:

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                     Source IPv4 address                       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                  Destination IPv4 address                     |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                 Figure 12: END-POINTS Object Body Format for IPv4  
        """
  
    def parse_endpoints_object(self, msg, com_obj_hdr, offset=0):
        if com_obj_hdr[1] == 1:
            endpointsv4_obj = struct.unpack_from(self._endpointsv4_obj_fmt,
                                                 msg[8+offset:])
            src_ipv4 = endpointsv4_obj[0]
            dst_ipv4 = endpointsv4_obj[1]
            return ('endpoints',(src_ipv4, dst_ipv4))
    """
The BANDWIDTH object may be carried within PCReq and PCRep messages.
   BANDWIDTH Object-Class is 5.
   Two Object-Type values are defined for the BANDWIDTH object:
   o  Requested bandwidth: BANDWIDTH Object-Type is 1.
   o  Bandwidth of an existing TE LSP for which a reoptimization is
      requested.  BANDWIDTH Object-Type is 2.
   The format of the BANDWIDTH object body is as follows:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Bandwidth                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    """

    def parse_bw_object(self, msg, com_obj_hdr, offset=0):
        bw_obj = struct.unpack_from(self._bw_obj_fmt,msg[8+offset:])
        print(bw_obj)
        return ('bw',(bw_obj[0],))



        """
        used in pcreq and pcrep
   METRIC Object-Class is 6.
   METRIC Object-Type is 1.
   The format of the METRIC object body is as follows:
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Reserved             |    Flags  |C|B|       T       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          metric-value                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
    def parse_metric_object(self, msg, com_obj_hdr, offset=0):
        metric_obj = struct.unpack_from(self._metric_obj_fmt,msg[8+offset:])
        metric_type = metric_obj[2]
        bound_flag = metric_obj[1]&1
        comp_met_flag = metric_obj[1]&2
        met_value = metric_obj[3]
        print(met_value)
        return ('metric',(metric_type, bound_flag, comp_met_flag, met_value))
  

        """
   The contents of an EXPLICIT_ROUTE object are a series of variable-
   length data items called subobjects:
    0                   1
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-------------//----------------+
   |L|    Type     |     Length    | (Subobject contents)          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-------------//----------------+
        """
    def parse_ero_subobject(self, ero_obj):
        tlv_type = struct.unpack_from("!BB",ero_obj)
        #loose or strict:
        l_flag = tlv_type[0]>>7
        sobj_type = tlv_type[0]&127
        sobj_length = tlv_type[1]
        #atm only ipv4 subobject will be implemented
        if sobj_type == 1:
            """
        0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |L|    Type     |     Length    | IPv4 address (4 bytes)        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | IPv4 address (continued)      | Prefix Length |      Resvd    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            """
            ero_sobj = struct.unpack_from("!BBIBB",ero_obj)
            return (sobj_length, l_flag, ero_sobj)
        #placeholder for safety, so we wont iterate forever if we dont know sobj_type (aka != 1)
        return(1000,None,None)

        """
        used in pcrep
        Object-Class = 7
        Object-Type = 1
        ero_size = value of length field in common obj hdr
        """

    def parse_ero_object(self, msg, com_obj_hdr, offset=0):
        parsed_ero_size = 0
        ero_list = list()
        while parsed_ero_size + 4 < com_obj_hdr[2]:
            sobj = self.parse_ero_subobject(msg[8+offset+parsed_ero_size:])
            parsed_ero_size += sobj[0]
            ero_list.append(sobj)
            print(sobj) 
        return ('ero',ero_list)


    """
    only ipv4 and lable subobjects will be implemented atm:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Type     |     Length    | IPv4 address (4 bytes)        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | IPv4 address (continued)      | Prefix Length |      Flags    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Length    |    Flags      |   C-Type      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       Contents of Label Object                                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    def parse_rro_subobject(self,rro_obj):
        tlv_type = struct.unpack_from("!BB",rro_obj)
        sobj_type = tlv_type[0]
        sobj_length = tlv_type[1]
        #atm only ipv4 and label subobjects will be implemented
        if sobj_type == 1:
            rro_sobj = struct.unpack_from("!BBIBB",rro_obj)
            return (sobj_length, rro_sobj)
        if sobj_type == 3:
            rro_sobj = struct.unpack_from("!BBBBI",rro_obj)
            return (sobj_length, rro_sobj)         
        #placeholder for safety, so we wont iterate forever if we dont know sobj_type (aka != 1)
        return(1000,None)


    """
        used in pcreq
        Object-Class = 8
        Object-Type = 1
    """
    def parse_rro_object(self, msg, com_obj_hdr, offset=0):
        parsed_rro_size = 0
        rro_list = list()
        while parsed_rro_size + 4 < com_obj_hdr[2]:
            sobj = self.parse_rro_subobject(msg[8+offset+parsed_rro_size:])
            parsed_rro_size += sobj[0]
            rro_list.append(sobj)
            print(sobj)
            print(self.int2ip(sobj[1][2]))
        return ('rro',rro_list)

    """
   LSPA Object-Class is 9.
   LSPA Object-Types is 1.
   The format of the LSPA object body is:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Exclude-any                             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Include-any                             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Include-all                             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Setup Prio   |  Holding Prio |     Flags   |L|   Reserved    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   //                     Optional TLVs                           //
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    def parse_lspa_object(self, msg, com_obj_hdr, offset=0):
        lspa_obj = struct.unpack_from(self._lspa_obj_fmt,msg[8+offset:])
        setup_pri = lspa_obj[3]
        hold_pri = lspa_obj[4]
        #local protection desired
        L_flag = lspa_obj[5]&1
        print("lspa obj: %s %s %s"%(setup_pri,hold_pri,L_flag,))
        return ('lspa',(setup_pri, hold_pri, L_flag))


        """
        TODO: need to implement it, gonna remove extensive description afterwards.
   IRO Object-Class is 10.
   IRO Object-Type is 1.
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   //                        (Sub-objects)                        //
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                    Figure 17: IRO Body Format

   Sub-objects:  The IRO is made of sub-objects identical to the ones
      defined in [RFC3209], [RFC3473], and [RFC3477], where the IRO sub-
      object type is identical to the sub-object type defined in the
      related documents.

      The following sub-object types are supported.

          Type   Sub-object
           1     IPv4 prefix
           2     IPv6 prefix
           4     Unnumbered Interface ID
           32    Autonomous system number
        """

    def parse_iro_object(self, msg, offset=0):
        pass
    """
       LSP Object-Class is 32.

   LSP Object-Type is 1.

   The format of the LSP object body is shown in Figure 11:

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                PLSP-ID                |     Flags |  O|A|R|S|D|
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     //                        TLVs                                 //
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    def parse_lsp_object(self, msg, com_obj_hdr, offset=0):
        lsp_obj = struct.unpack_from(self._lsp_obj_fmt,msg[8+offset:])
        plsp_id = lsp_obj[0] >> 12
        """
           Flags (12 bits):

   D (Delegate - 1 bit):
   S (SYNC - 1 bit): 
   R(Remove - 1 bit): 
   A(Administrative - 1 bit): 
   O(Operational - 3 bits):  
      0 - DOWN:  not active.
      1 - UP:  signalled.
      2 - ACTIVE:  up and carrying traffic.
      3 - GOING-DOWN:  LSP is being torn down, resources are being
      4 - GOING-UP:  LSP is being signalled.
      5-7 - Reserved:  these values are reserved for future use.
        """
        d_flag = lsp_obj[0] & 1
        s_flag = lsp_obj[0] & 2
        r_flag = lsp_obj[0] & 4
        a_flag = lsp_obj[0] & 8
        o_flag = lsp_obj[0] & 112
        if com_obj_hdr > 8:
            print('lsp_obj has TLVs')
            #TODO: add tlv's parsing
        return ('lsp_obj',(plsp_id,d_flag,s_flag,r_flag,a_flag,o_flag))

    def parse_error_msg(self, common_hdr, msg):
        self.parse_common_obj_hdr(msg)
        error_msg = struct.unpack_from(self._error_obj_fmt,msg[8:])
        print(error_msg)
 
    def parse_state_report_msg(self,common_hdr, msg):
        offset = 0
        parsed_state_report = list()
        while offset+4 < common_hdr[2]:
            parsed_obj_hdr=self.parse_common_obj_hdr(msg,offset)
            if (parsed_obj_hdr[0],parsed_obj_hdr[1]) in self._functions_dict:
                #lspa = self.parse_lspa_object(msg, parsed_obj_hdr, offset)
                oc_ot = (parsed_obj_hdr[0],parsed_obj_hdr[1])
                parsed_obj = self._functions_dict[oc_ot](msg,parsed_obj_hdr,
                                                         offset)
                parsed_state_report.append(parsed_obj)
            else:
                parsed_state_report.append(('unknow obj',))
            offset+=parsed_obj_hdr[2]
        print('parsed_state_report:')
        print(parsed_state_report)
        return('state_report',parsed_state_report)
   
    def generate_nopath_obj(self, NI_flag=0, C_flag=0):
        """
        used in pcrep
        Object-Class = 3
        Object-Type = 1
   The format of the NO-PATH object body is as follows:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Nature of Issue|C|          Flags              |   Reserved    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   //                      Optional TLVs                          //
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                 Figure 11: NO-PATH Object Format
        """
        C_flag <<=15
        #TODO: NO-PATH-VECTOR
        return struct.pack(self._nopath_obj_fmt,NI_flag,C_flag,0)
   
    def generate_open_msg(self,ka_timer):
        self._ka_timer = ka_timer
        common_hdr = struct.pack(self._common_hdr_fmt,32,1,20)
        common_obj_hdr = struct.pack(self._common_obj_hdr_fmt,1,16,16)
        open_obj = struct.pack(self._open_obj_fmt,32,ka_timer,ka_timer*4,self._open_sid)
        return join((common_hdr,common_obj_hdr,open_obj,self._spc_tlv),sep='')

    def generate_ka_msg(self):
        common_hdr = struct.pack(self._common_hdr_fmt,32,2,4)
        return common_hdr

    def parse_ka_msg(self,common_hdr,msg):
        return ('ka_msg',)
        
        
