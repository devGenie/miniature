## Miniature ##

Miniature is an vpn server and client written in go. Miniature uses songao's water library under the hood.

**Setup**

``` 
git clone https://github.com/devGenie/miniature

cd miniature 

export GO111MODULE=on 

go mod init github.com/devgenie/miniature

```

To build and run the VPN server

```
go build ./cmd/server

./server run -config=/etc/miniature/config.yml
```

`-config` is the path to the VPN server's configuration file, the VPN server's configuration file looks like;

```
certificatesdirectory: /etc/miniature/certs

network: 10.2.0.0/24

listeningport: 4321

publicip: 172.18.0.2

dnsresolvers:
    - 1.1.1.1
```

You can also start the server using `./server run`. This will use the default path to the configuration file (`/etc/miniature/config.yml`)

To create a client configuration file
`./server newclient --config=/etc/miniature/config.yml`

`-config` is the path to the server configuration file, you can also create the client configuration file using `./server newclient`, this uses the server's default path to the configuration file, in this case which is `/etc/miniature/config.yml`


To build and run the VPN client:

```
go build ./cmd/client

./client -config=/etc/miniature/config.yml
```

`-config` is used to specify the path to the  client configuration file. If this command line switch is not provided, the client will use the default path which is `/etc/miniature/config.yml`. The config file looks like an example below:

```
serveraddress: 172.2.2.2
listeningport: 4321
certificate: |
    -----BEGIN CERTIFICATE-----
    MIIDwDCCAqigAwIBAgIIEt8f19aYOP4wDQYJKoZIhvcNAQELBQAwcDEPMA0GA1UE
    BhMGVWdhbmRhMQkwBwYDVQQIEwAxCTAHBgNVBAcTADEJMAcGA1UECRMAMQkwBwYD
    VQQREwAxEjAQBgNVBAoTCUdlbmllTGFiczEJMAcGA1UECxMAMRIwEAYDVQQDEwlH
    ZW5pZUxhYnMwHhcNMTkwNzAyMjMyMjAwWhcNMjQxMjA3MjMyMjAwWjBwMQ8wDQYD
    VQQGEwZVZ2FuZGExCTAHBgNVBAgTADEJMAcGA1UEBxMAMQkwBwYDVQQJEwAxCTAH
    BgNVBBETADESMBAGA1UEChMJR2VuaWVMYWJzMQkwBwYDVQQLEwAxEjAQBgNVBAMT
    CUdlbmllTGFiczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKsjiB4T
    IZb5muzLVRCWf3Z1f7kub4l9/psyLL6FyOfdjvdbOP+fc1XxFd40G2fROFCAiZOw
    2SFg/HLxDJt/RqX38e40Uto+RjUAj67k+B59A4JIP52+tqv4N9J1Q1IoQEKotQIB
    Ej6Ug5evKp2cQ7Ui731IvGzTwuacYoU6UkU+1rfw4L0SdAC1hjQ6S11WzitcRNTu
    aCx6tj+F+C/bvTwcneHmJjHbOT135jWyjLKSZzv1zNP3C8fDdj6/auTsCW7kSIyt
    G8e3c0/tpmP6YG5TeYyVOysPMnfcqJPDnJPrWIztOxYmhv1etPXR0wxZp83i6Rhe
    jHqyi9A2tPQiL0kCAwEAAaNeMFwwDgYDVR0PAQH/BAQDAgKEMB0GA1UdJQQWMBQG
    CCsGAQUFBwMCBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQAxYvP
    p4gWbBUK7RxG6dTdQ922qTANBgkqhkiG9w0BAQsFAAOCAQEArSBO+rMyoAWkCiBu
    6RGdYy80KoCVKF3wNL8fEiXvMXZcnlyxF1GGyKTEWTVlelzMvauvNdhbtDEWKGqt
    UD3euOV+S6+/JNbHLIOlcj4N4pZRlSw8iTf9MPb7dGu/h4StXbIwSFgkVwyeiHWD
    vFaP1djY/6Ng1QDfaGN1fe/iFACvEpJAdiizq16eee3/y2ywFzZEqtk5mNoXSvHI
    MS9dGE1YxIYJtPeqw2ZsTtRIa+1XsCiUp0nqRya9bK1eJFmO7oYFKZnSQ89JnNeN
    5eVwLDYsbrfU14kWHf9e2S3LXYqGROVSyIgVsMSyjcZJ1ipLFl9xqg3AY5O0yHRq
    y4ylDg==
    -----END CERTIFICATE-----
privatekey: |
    -----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEAqyOIHhMhlvma7MtVEJZ/dnV/uS5viX3+mzIsvoXI592O91s4
    /59zVfEV3jQbZ9E4UICJk7DZIWD8cvEMm39Gpffx7jRS2j5GNQCPruT4Hn0Dgkg/
    nb62q/g30nVDUihAQqi1AgESPpSDl68qnZxDtSLvfUi8bNPC5pxihTpSRT7Wt/Dg
    vRJ0ALWGNDpLXVbOK1xE1O5oLHq2P4X4L9u9PByd4eYmMds5PXfmNbKMspJnO/XM
    0/cLx8N2Pr9q5OwJbuRIjK0bx7dzT+2mY/pgblN5jJU7Kw8yd9yok8Ock+tYjO07
    FiaG/V609dHTDFmnzeLpGF6MerKL0Da09CIvSQIDAQABAoIBAEJBM0VRasOkRpI9
    9eTCHv6hZp0umQfFu3gh6Kip6qm5YMvqiRqNhH1VJH4t9h4vJXolCR4gbS86+QEW
    ySa6E4PVhdgOcbUEPvHuEbJH+rby9xTNG7PaTaYuJo5Xz4RTCO3Fmq339DQ+EuP6
    cKksAhpyN/1s12XaZa4aBRpHBerAUq8N01rYWgJ1uH/7ILKtaZMg/tBbUHqqPd0G
    oWcub/zbAmGmU3MqZMtY8VG1DsDQ8nlGsFdJnyHX9NFisPOiP3ytk1kBuIHN3yQT
    S3AG1FWu/PkYqZtho+dl4MI/osMmRoZLY62zDMASByeqQ5bO619UQ5TPl0XXDnkz
    tuplecECgYEAwwdym/yaykcjv34A8sgkSvPMr4TCsUkPZNAoijZWjuXlD9iMDKhK
    ITFiZtOHxdS9yNmWr7KUB6t3Amw7BAVRUU+9prYGi3069BVnMZP5PGa0xM8/UgqW
    KtrljHDydWGYq/9vNCFNDVg5CW7uBZEc2jZtL+fuKtbLcMpoG/5aWo0CgYEA4KQZ
    BdMd0HEL1W0EBjs2/WuElfxSnMvSZAxRYMJFDudma3tw5EnHvbSG3E32oLU7YYpG
    emvpL9NB2fVkiN99ylWqciXdjuxsv0y+POvpCuFyXVH2g5T/g7+TYU+SV/aKRcBd
    wpOYl8MbLzPlgVpHZUe2l48XGv8sHfdgaj4udq0CgYARm7GITdU34BZlKp4xTUqh
    jcN0MVtWoE8Ifha6688C1dTJinaSifsvZgMJX53JibyczrBhKpFc4+k5ycXGRiii
    W722uIZ8v5C8CtanTkHZZzh48HE6GgSW1+6TsHrjiC09kjFbFoqbYtS7ek15KTHe
    rb1L7ve83Gm/xDaEGIHV3QKBgQDax5bDMHhB8Ec5JgIcW4FT0GoBdQu0P2F5JPIA
    jVOaj00VctRg0WZh4LbTSm7e14KsnXHEeuJRPKtOrgqqrxcgfswQfcZJEwNaUFCa
    npuJiEXMky3FutAbLPJJfKinWKoUAqSOAxdC/ra0AxQLJbSQ9AXll2tGVKxPxwQ0
    lLjFxQKBgQCUkn1Y2yad4fLb+prcurtuIwBSqpXt/eX/SmT87b0G50VPR0vZQzNw
    v7tHAZear2HgMdM8s4c2h6Ye+hBDssEqg9TP6JrXcmXUOG8UST4w3PF8DPtJH/Vr
    bKLdmSN6GJJcT7lcwtXYNA6/ygkuMzySfBPLItkHQ+yPI9b2P8YKGA==
    -----END RSA PRIVATE KEY-----
```

To generate a config file like the one above, run `./server newclient --config=/etc/miniature/config.yml`

**Note**

At the moment, the VPN server runs on only linux, plans are to port it to windows sometime. At the moment, it is not possible to port it to OSX because of the limitations in configuring the tun interfaces

The client has only been tested only on linux at the moment.Plans are to port it to both osx and windows in the future.

**Note**

Development has been done on Linux, if you don"t have a linux machine, you can use docker containers to run a dev environment. Right now, it is not possible to develop the server on OSX. This has not been tested on windows yet.

The docker containers have to be run in privelege mode to make this work as expected.

```
docker network create miniature 

docker build -t miniature .

docker run -dit --mount type=bind,source="$(pwd)",target=/miniature --privileged --name miniature-server --network miniature miniature

//mount the current working directory to so that the changes made in you code editor are available inside the docker containers

docker run -dit --mount type=bind,source="$(pwd)",target=/miniature --privileged --name miniature-client1 --network miniature miniature

docker run -dit --mount type=bind,source="$(pwd)",target=/miniature --privileged --name miniature-client2 --network miniature miniature
```

**Todo**

- [x] Encryption/ Decryption

- [x] Authentication

- [x] Compression using LZO

- [x] Data Fragmentation/ Defragmentation

- [x] DNS Forwarding