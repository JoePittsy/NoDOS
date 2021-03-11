import os

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk
from gi.repository.GLib import timeout_add_seconds
from utils import *
from operator import itemgetter
from collections import defaultdict
import sys
from gi.repository import GdkPixbuf

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)


class NoDOS:
    def __init__(self):
        self.threshold = 100
        self.under_attack = False
        self.builder = Gtk.Builder()
        path = resource_path("NoDOS.glade")
        self.builder.add_from_file(path)
        # builder.connect_signals(Handler())
        self.window = self.builder.get_object("window1")

        self.window.connect("destroy", Gtk.main_quit)
        self.ip_store = self.builder.get_object("active_store")
        self.rule_store = self.builder.get_object("rule_store")

        self.ip_entry = self.builder.get_object("ip_entry")
        self.con_spinner = self.builder.get_object("connections_spinner")
        self.block_check = self.builder.get_object("block_check")
        self.block_check_global = self.builder.get_object("block_check_global")
        self.global_block = False
        self.window.show_all()

        self.ip_rows = {}
        self.rules = []

        self.ip_rules = []

        handlers = {
            "onDestroy": self.quit,
            "onRuleAdd": self.add_rule,
            "ruleKeyPress": self.delete_rules,
            "thresholdChanged": self.threshold_changed,
            "showAbout": self.show_about,
            "aboutResponse": self.hide_about,
            "globalBlockToggle": self.block_toggle
        }
        self.builder.connect_signals(handlers)

        self.conn_column = self.builder.get_object("connection column")
        self.conn_column.set_sort_column_id(0)
        # self.about.show_all()/
        self.root = False
        # We are root
        if os.geteuid() == 0:
            self.root = True
            self.block_check_global.set_sensitive(True)
            self.block_check.set_sensitive(True)
            self.block_check_global.set_tooltip_text("")
            self.block_check.set_tooltip_text("")

    def block_toggle(self, e):
        self.global_block = e.get_active()

    def quit(self, *args):
        self.window.hide()
        raise SystemExit

    def show(self):
        self.update_ip_store()

        # timeout_add_seconds(1, self.add_to_liststore)
        timeout_add_seconds(1, self.update_ip_store)

        Gtk.main()

    def show_about(self, e):
        about = Gtk.AboutDialog()
        about.set_program_name("NoDos")
        about.set_version("1.0")
        about.set_copyright("(c) Joe Pitts")
        about.set_comments("NoDOS monitors network traffic and warns you about potential DOS attacks.")
        about.set_website_label("Github")
        about.set_website("https://github.com/JoePittsy/NoDOS")
        about.add_credit_section("Creator", ["Joseph Pitts"])
        about.set_license_type(Gtk.License(10))
        path = resource_path("./logo.png")
        about.set_logo(GdkPixbuf.Pixbuf.new_from_file(path))
        about.run()
        about.destroy()

    def hide_about(self, e, a):
        e.hide()
        return True

    def threshold_changed(self, e):
        self.threshold = e.get_value()

    def update_ip_store(self):
        connections = get_active_connections()
        current_ips = [self.ip_store[key][1] for key in self.ip_rows.values()]
        new_ips = []

        rules = [self.rule_store[rule][:] for rule in self.rules]
        rule_ips = [r[0] for r in rules]
        possible_attack = False
        attacks = []

        rule_count = defaultdict(int)

        def ip_equal_rule(ip, rule):
            split_ip = ip.split(".")
            split_rule = rule.split(".")
            match = True
            for i in range(len(split_rule)):
                if split_rule[i] == "x":
                    continue
                if split_ip[i] != split_rule[i]:
                    match = False
                    break
            return match

        for ip, cons in sorted(connections.items(), key=itemgetter(1), reverse=True):
            # Update existing rows.
            new_ips.append(ip)
            if ip in current_ips:
                self.ip_store[self.ip_rows[ip]][0] = cons
                self.ip_store[self.ip_rows[ip]][2] = "white"
                self.ip_store[self.ip_rows[ip]][3] = "Dim Gray"

            else:
                self.ip_rows[ip] = self.ip_store.append([cons, ip, "white", "Dim Gray"])

            if cons > self.threshold:
                possible_attack = True
                self.ip_store[self.ip_rows[ip]][2] = "red"
                self.ip_store[self.ip_rows[ip]][3] = "white"

                attacks.append([ip, cons])
                if self.global_block and self.root:
                    block_ip(ip)

            if ip in rule_ips:
                id = rule_ips.index(ip)
                if cons > rules[id][1]:
                    possible_attack = True
                    self.ip_store[self.ip_rows[ip]][2] = "red"
                    self.ip_store[self.ip_rows[ip]][3] = "white"

                    attacks.append([ip, cons])

                    if rules[id][2] and self.root:
                        block_ip(ip)

            for rule in rule_ips:
                if "x" in rule:
                    match = ip_equal_rule(ip, rule)
                    if match:
                        rule_count[rule] += cons

        for key, count in rule_count.items():
            rule = rules[rule_ips.index(key)]
            if count > rule[1]:
                attacks.append([key, count])
                possible_attack = True
                for ip, cons in sorted(connections.items(), key=itemgetter(1), reverse=True):
                    if ip_equal_rule(ip, key):
                        self.ip_store[self.ip_rows[ip]][2] = "red"
                        self.ip_store[self.ip_rows[ip]][3] = "white"
                        if rule[2] and self.root:
                            block_ip(ip)

        s = set(new_ips)
        old_ips = [x for x in current_ips if x not in s]
        for ip in old_ips:
            self.ip_store.remove(self.ip_rows[ip])
            self.ip_rows.pop(ip)

        if not self.under_attack and possible_attack:
            for attacker in attacks:
                self.show_popup(attacker[0], attacker[1])
                self.under_attack = True

        if not possible_attack:
            self.under_attack = False
        return True

    def add_rule(self, button):
        ip = self.ip_entry.get_text()
        allowed_cons = self.con_spinner.get_value()
        auto_block = self.block_check.get_active()

        self.rules.append(self.rule_store.append([ip.lower(), allowed_cons, auto_block]))

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

        dialog.destroy()

    def delete_rules(self, tree, key):
        # Delete Key
        if key.keyval == 65535:
            selection = tree.get_selection()
            model, paths = selection.get_selected_rows()
            iters = []
            ids = []
            for path in paths:
                iters.append(self.rules[int(path.to_string())])
                ids.append(int(path.to_string()))
            for iter in iters:
                self.rule_store.remove(iter)
            for id in sorted(ids, reverse=True):
                self.rules.pop(id)


if __name__ == "__main__":
    noDOS = NoDOS()
    noDOS.show()
    raise SystemExit
