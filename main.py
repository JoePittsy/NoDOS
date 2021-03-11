import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk
from gi.repository.GLib import timeout_add_seconds
from sniffer import get_active_connections
from operator import itemgetter


class NoDOS:
    def __init__(self):
        self.threshold = 100
        self.under_attack = False
        self.builder = Gtk.Builder()
        self.builder.add_from_file("NoDOS.glade")
        # builder.connect_signals(Handler())
        self.window = self.builder.get_object("window1")
        self.window.connect("destroy", Gtk.main_quit)
        self.ip_store = self.builder.get_object("active_store")

        self.window.show_all()

        self.ip_rows = {}

        handlers = {
            "onDestroy": Gtk.main_quit,
        }
        self.builder.connect_signals(handlers)

    def show(self):
        self.add_to_liststore()

        # timeout_add_seconds(1, self.add_to_liststore)
        timeout_add_seconds(2, self.update_ip_store)

        Gtk.main()

    def update_ip_store(self):
        connections = get_active_connections()
        print(self.ip_store[self.ip_rows["192.168.1.1"]][:])
        current_ips = [self.ip_store[key][1] for key in self.ip_rows.values()]
        new_ips = []
        for ip, cons in sorted(connections.items(), key=itemgetter(1), reverse=True):
            # Update existing rows.
            new_ips.append(ip)
            if ip in current_ips:
                self.ip_store[self.ip_rows[ip]][0] = cons
            else:
                self.ip_rows[ip] = self.ip_store.append([cons, ip])

        s = set(new_ips)
        old_ips = [x for x in current_ips if x not in s]
        print(f"Old Ips: {old_ips}")
        for ip in old_ips:
            print(ip)
            self.ip_store.remove(self.ip_rows[ip])
            self.ip_rows.pop(ip)
        return True

    def add_to_liststore(self):
        print("Called")
        connections = get_active_connections()
        self.ip_store.clear()
        possible_attack = False
        attacker = []
        for key, value in sorted(connections.items(), key=itemgetter(1), reverse=True):
            if value > self.threshold:
                possible_attack = True
                attacker.append(key)
                attacker.append(value)

            self.ip_rows[key] = self.ip_store.append([value, key])

        if not self.under_attack and possible_attack:
            self.show_popup(attacker[0], attacker[1])
            self.under_attack = True

        if not possible_attack:
            self.under_attack = False

        return True

    def show_popup(self, ip, cons):
        dialog = Gtk.MessageDialog(
            transient_for=self.window,
            flags=0,
            message_type=Gtk.MessageType.ERROR,
            buttons=Gtk.ButtonsType.OK,
            text="Ongoing DOS attack!",
        )
        dialog.format_secondary_text(
            f"The IP {ip} has {cons} active connections!"
        )
        dialog.run()
        print("ERROR dialog closed")

        dialog.destroy()


if __name__ == "__main__":
    noDOS = NoDOS()
    noDOS.show()
