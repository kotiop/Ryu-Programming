from ryu.base import app_manager

class MyFirstRyuApp(app_manager.RyuApp):
    def __init__ (self, *args, **kwargs):
        super(MyFirstRyuApp, self).__init__(*args, **kwargs)
        print("My first Ryu app has started")