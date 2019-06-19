## Miniature ##

Miniature is an openvpn server and client written in go. Miniature uses songao's water library under the hood.

**Setup**

``` 
git clone https://github.com/devGenie/miniature

cd miniature 

export GO111MODULE=on 

go mod init github.com/devgenie/miniature

go build
```

To run the VPN server:

`` ./miniature --type=server ``

To run the VPN client:

`` ./minature --type=client --remote=remote-server-address ``

**Note**

At the moment, the VPN server runs on only linux, plans are to port it to windows sometime. At the moment, it is not possible to port it to OSX because of the limitations in configuring the tun interfaces

The client has only been tested only on linux at the moment.Plans are to port it to both osx and windows in the future.

**Todo**

- [ ] Encryption/ Decryption

- [ ] Authentication

- [ ] Compression using LZO

- [ ] Data Fragmentation/ Defragmentation

- [ ] DNS Forwarding