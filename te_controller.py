import socket
import mpls_lsp_pb2
import struct

class TEController(object):
    def __init__(self):
        self.lsp_dict = dict()

    def ip2int(self, addr):
        return struct.unpack_from("!I", socket.inet_aton(addr))[0]
    def int2ip(self, addr):
        return socket.inet_ntoa(struct.pack("!I", addr)) 

    def handle_pce_message(self, pcc_ip, message):
        if message[0] == 'state_report':
            self.handle_state_report(pcc_ip, message)

    def handle_state_report(self, pcc_ip, message):
        lsp = mpls_lsp_pb2.LSP()
        first_lsp = 1
        for report_object in message[1]:
            if report_object[0] == 'lsp_obj':
                if first_lsp != 1:
                    lsp_dict_index = (self.ip2int(pcc_ip[0]),lsp.lsp_obj.plsp_id)
                    new_lsp = mpls_lsp_pb2.LSP()
                    new_lsp.CopyFrom(lsp)
                    self.lsp_dict[lsp_dict_index] = new_lsp
                else:
                    first_lsp = 0
                lsp.Clear()
                lsp.pcc_ip = pcc_ip[0]
                lsp.lsp_obj.plsp_id = report_object[1][0]
                lsp.lsp_obj.delegated = report_object[1][1]
                lsp.lsp_obj.administrative = report_object[1][4]
                lsp.lsp_obj.operational = report_object[1][5]
            if report_object[0] == 'bw':
                lsp.bandwidth = report_object[1][0]
            if report_object[0] == 'lspa':
                lsp.lspa_obj.setup_prio = report_object[1][0]
                lsp.lspa_obj.hold_prio = report_object[1][1]
                lsp.lspa_obj.local_protection = report_object[1][2]
            if report_object[0] == 'ero':
                if len(report_object[1]) > 0:
                    for ero_node in report_object[1]:
                        ero = lsp.ero.add()
                        ero.loose = ero_node[1]
                        ero.node_ip = self.int2ip(ero_node[2][2])
                        ero.node_mask = ero_node[2][3]
            if report_object[0] == 'rro':
                if len(report_object[1]) > 0:
                    for rro_node in report_object[1]:
                        rro = lsp.rro.add()
                        rro.node_ip = self.int2ip(rro_node[1][2])
                        rro.node_mask = rro_node[1][3]
        lsp_dict_index = (self.ip2int(pcc_ip[0]),lsp.lsp_obj.plsp_id)
        self.lsp_dict[lsp_dict_index] = lsp
        for lsp in self.lsp_dict:
            print(self.lsp_dict[lsp])
