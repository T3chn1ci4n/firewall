from netfilterqueue import NetfilterQueue
from scapy.all import *
import time
import json

# Tries to open file
try:
    f = open("firewalls.json", 'r')
    y = json.load(f)
    f.close()

    # Check if ListOfBannedIpAddress exists in rule file
    if ("ListOfBannedIpAddress" in y):
        if (type(y["ListOfBannedIpAddress"])==list):
            ListOfBannedIpAddress = y["ListOfBannedIpAddress"]
        else:
            print("Invalid ListOfBannedIpAddress in rule file. Setting to default []")
            ListOfBannedIpAddress = []
    else:
        print("ListOfBannedIpAddress missing in rule file. Setting to default []")
        ListOfBannedIpAddress = []

    # Check if ListOfBannedPorts exists in rule file
    if ("ListOfBannedPorts" in y):
        if (type(y["ListOfBannedPorts"])==list):
            ListOfBannedPorts = y["ListOfBannedPorts"]
        else:
            print("Invalid ListOfBannedPorts in rule file. Setting to default []")
            ListOfBannedPorts = []
    else:
        print("ListOfBannedPorts missing in rule file. Setting to default []")
        ListOfBannedPorts = []

    # Check if ListOfBannedPrefixes exists in rule file
    if ("ListOfBannedPrefixes" in y):
        if (type(y["ListOfBannedPrefixes"])==list):
            ListOfBannedPrefixes = y["ListOfBannedPrefixes"]
        else:
            print("Invalid ListOfBannedPrefixes in rule file. Setting to default []")
            ListOfBannedPrefixes = []
    else:
        print("ListOfBannedPrefixes missing in rule file. Setting to default []")
        ListOfBannedPrefixes = []

    # Check if TimeThreshold exists in rule file
    if ("TimeThreshold" in y):
        if(type(y["TimeThreshold"])==int):
            TimeThreshold = y["TimeThreshold"]
        else:
            print("Invalid time threshold in rule file. Setting to default 10")
            TimeThreshold = 10
    else: 
        print("TimeThreshold missing in rule file. Setting to default 10")
        TimeThreshold = 10

    # Check if PacketThreshold exists in rule file
    if ("PacketThreshold" in y):
        if(type(y["PacketThreshold"])==int):
            PacketThreshold = y["PacketThreshold"]
        else:
            print("Invalid time threshold in rule file. Setting to default 100")
            PacketThreshold = 100
    else: 
        print("PacketThreshold missing in rule file. Setting to default 100")
        PacketThreshold = 100

    # Check if BlockPingAttacks exists in rule file
    if ("BlockPingAttacks" in y):
        if(type(y["BlockPingAttacks"])==int):
            BlockPingAttacks = y["BlockPingAttacks"]
        else:
            print("Invalid block ping attack in rule file. Setting to default True")
            BlockPingAttacks = True
    else:
        print("Invalid block ping attack in rule file. Setting to default True")
        BlockPingAttacks = True

    
    
# Will run if file doesn't exist
except FileNotFoundError:
    print("Json file was not found, Default Settings Initiated")
    # List of Banned Ip/Port/Prefixes
    ListOfBannedIpAddress = []
    ListOfBannedPort = []
    ListOfBannedPrefixes = []
    # Threshold for packet/timeout
    TimeThreshold = 10 #Seconds
    PacketThreshold = 100
    BlockPingAttacks = True

# Function for the firewall
def firewall(pkt):
    sca = IP(pkt.get_payload())

    # Check if IP address is in banned list
    if (sca.src in ListOfBannedIpAddress):
        print(f"{sca.src} is incoming IP address that is banned by firewall.")
        pkt.drop()
        return

    # Check if TCP port is in banned list
    if (sca.haslayer(TCP)):
        t = sca.getlayer(TCP)
        if(t.dport in ListOfBannedPorts):
            print(f"{sca.dport} is a destination port that is banned by firewall")
            pkt.drop()
            return

    # Check if UDP port is in banned list
    if (sca.haslayer(UDP)):
        t = sca.getlayer(UDP)
        if(t.dport in ListOfBannedPorts):
            print(f"{t.dport} is destination port that is banned by firewall firewall")
            pkt.drop()
            return
    # Check if Prefix is in banned list
    if (True in [sca.src.find(suff)==0 for suffix in ListOfBannedPrefixes]):
        print(f"Prefix of sca.src is banned by firewall.")
        pkt.drop()
        return
    # Prevention for flood attacks
    if (BlockPingAttacks and sca.haslayer(ICMP)):
        t = sca.getlayer(ICMP)
        if (t.code==0):
            if(sca.src in DictOfPackets):
                # Detects if there is a flood attacks by checking value of threshold
                temptime = list(DictOfPackets[sca.src])
                if (len(DictOfPackets[sca.src]) >= PacketThreshold):
                    if (time.time() - DictOfPackets[sca.src][0] <= TimeThreshold):
                        print(f"Ping by %s blocked by firewall (too many requests in short span of time)." %(sca.src)) 
                        pkt.drop()
                        return
                    else:
                        DictOfPackets[sca.src].pop(0)
                        DictOfPackets[sca.src].append(time.time())
                else:
                    DictOfPackets[sca.src].append(time.time())
            else:
                DictOfPackets[sca.src] = [time.time()]

        print("Packet from %s accepted and forwarded to IPTABLES" %(sca.src))
        pkt.accept()
        return

    print("Packet from %s accepted and forwarded to IPTABLES" %(sca.src))

# Filters the packets
nfqueue = NetfilterQueue()
nfqueue.bind(1,firewall)

# will try to run 
try: nfqueue.run()
# will exit if key if press
except KeyboardInterrupt: pass

nfqueue.unbind()
