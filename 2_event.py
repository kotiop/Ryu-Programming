from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls

class MyRyuApp(app_manager.RyuApp):
    def __init__(self, *_args, **_kwargs):
        super(MyRyuApp, self).__init__(*_args, **_kwargs)
        print("Ryu app has started")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_connected(self, ev):
        print("Switch Connected")