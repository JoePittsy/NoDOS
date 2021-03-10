import gi
import random
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk
from gi.repository.GLib import timeout_add_seconds
from sniffer import get_active_connections
from operator import itemgetter


class Handler:
    def onDestroy(self, *args):
        Gtk.main_quit()

    def onButtonPressed(self, button):
        print("Hello World!")


def add_to_liststore():
    print("Called")
    store = builder.get_object("active_store")
    connections = get_active_connections()
    store.clear()
    for key, value in sorted(connections.items(), key=itemgetter(1), reverse=True):
        store.append([value, key])
        # print(key, value)
    return True



builder = Gtk.Builder()
builder.add_from_file("NoDOS.glade")
# builder.connect_signals(Handler())

window = builder.get_object("window1")
window.show_all()

add_to_liststore()

timeout_add_seconds(1, add_to_liststore)

Gtk.main()
