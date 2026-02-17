from ryu.base import app_manager
from ryu.lib import hub
import os
import socket
import struct

class SnortManualIntegration(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(SnortManualIntegration, self).__init__(*args, **kwargs)
        self.socket_path = "/tmp/snort_alert"       # Socket file path
        
        # ----- Clean up old socket if it exists -----
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)             # Delete old file
        

        self.logger.info(f"Creating Manual Socket at {self.socket_path}")
        self.threads.append(hub.spawn(self._listen_to_snort))       # Ryu is an asynchronous framework. 
                                                                    # This line starts a background thread (a "GreenThread") so that the socket listener can run constantly without freezing the rest of your controller.

    def _listen_to_snort(self):
        # Create a Unix Domain Socket (Datagram)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.bind(self.socket_path)

        # AF_UNIX means the communication stays inside your pc (faster than network-based sockets)
        # SOCK_DGRAM tells Python to expect "Datagrams" (packets), which is what Snort sends when you use the -A unsock flag
        
        os.chmod(self.socket_path, 0o777)                           # Give permissions so Snort (running as sudo) can write to it
        
        self.logger.info("Waiting for Snort alerts...")
        
        while True:
            data = sock.recv(65535)                 # This puts the script into a "waiting" state. It pauses here until Snort detects a rule violation and pushes data into the socket.
                                                    # Captures the raw binary alert "Alertpkt"
            if data:
                self.logger.info("!!! ALERT RECEIVED FROM SNORT !!!")       # Just saying that the alert was received
                self.logger.info(f"Raw Data Length: {len(data)} bytes")