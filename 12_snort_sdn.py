from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
import os
import socket

class SnortSdnController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SnortSdnController, self).__init__(*args, **kwargs)
        self.socket_path = "/tmp/snort_alert"
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)
            
        self.logger.info(f"Creating Manual Socket at {self.socket_path}")
        self.threads.append(hub.spawn(self._listen_to_snort))

    # --- PART 1: SNORT ALERT LISTENER (Background Thread) ---
    def _listen_to_snort(self):
        self.logger.info("DEBUG: Socket is alive and waiting...")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.bind(self.socket_path)
        os.chmod(self.socket_path, 0o777)
        
        self.logger.info("IDS Listener: Waiting for Snort alerts...")
        
        while True:
            data = sock.recv(65535)
            if data:
                self.logger.info("!!! IDS ALERT RECEIVED FROM SNORT !!!")
                self.logger.info(f"Alert Data Size: {len(data)} bytes")

    # --- PART 2: Table Flow-Miss Handler---

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_connected(self, ev):
        self.logger.info("---- SDN Switch Connected: Installing Table-Miss ----")
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # TABLE-MISS FLOW: Match all, Send to Controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    # --- Part 3: Flooding ---
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)