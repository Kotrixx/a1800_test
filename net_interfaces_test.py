# Import libraries
import netifaces

# Showing gateway list
netifaces.gateways()

# Getting interfaces
interfaces = netifaces.interfaces()

# Showing interfaces
for interface in interfaces:
    print(interface)

    # Getting interface info
    print(netifaces.ifaddresses(str(interfaces[0])))

    # Getting interface status
    addrs = netifaces.ifaddresses(str(interfaces[0]))
    print(addrs[netifaces.AF_INET])
    print(addrs[netifaces.AF_LINK])