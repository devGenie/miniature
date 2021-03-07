#!/bin/sh
# Disable IPv6 on all interfaces.

DNS=$1
IFS=$'\n'
net=`networksetup -listallnetworkservices | grep -v asterisk`
for i in $net
do
    networksetup -setv6off "$i"
    echo "IPv6 for $i is Off"
    echo "Setting dns for $i"
    networksetup -setdnsservers "$i" empty
    networksetup -setdnsservers "$i" "$DNS"
    sudo killall -HUP mDNSResponder
    echo "$i Configured successfully"
done

exit 0