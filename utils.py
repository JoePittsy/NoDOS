import subprocess
import pprint


def get_active_connections():
    command = "netstat -ntu | awk '{print $5}' | cut -d: -f1 -s | sort | uniq -c | sort -nk1 -r"
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    output, error = proc.communicate()

    raw = str(output)[2:-3].split("\\n")

    raw = [ip.strip().split() for ip in raw]

    ips = {pair[1]: int(pair[0]) for pair in raw}

    return ips

def block_ip(ip):
    command = f"sudo iptables -A INPUT -s {ip} -j DROP"
    print(command)
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)

def unblock_ip(ip):
    command = f"sudo iptables -D INPUT -s {ip} -j DROP"
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)

