from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel
import os


class MyTopo(Topo):

    def build(self):
        s1 = self.addSwitch('s1')

        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        ids = self.addHost('ids')

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(ids, s1)


if __name__ == '__main__':

    setLogLevel('info')

    topo = MyTopo()

    net = Mininet(topo=topo, controller=None)

    net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6653
    )

    net.start()

    # ================= MIRROR TRAFFIC TO IDS =================

    print("*** Setting OVS mirror to IDS (s1-eth3)")

    os.system("""
    ovs-vsctl \
    -- --id=@ids get Port s1-eth3 \
    -- --id=@m create Mirror name=ids-mirror select-all=true output-port=@ids \
    -- set Bridge s1 mirrors=@m
    """)

    # =========================================================

    CLI(net)
    net.stop()
