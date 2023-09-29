## Using nip.io under DNS rebinding protection

Some networks block [DNS rebinding](https://en.wikipedia.org/wiki/DNS_rebinding),
which means nip.io cannot be used to resolve DNS queries. In this case, you 
have a few options:

1. run your own local instance of nip.io and configure your DNS resolver to use it
2. use a VPN provider that does not block DNS rebinding, such as Cloudflare WARP

This document details how to run a local nip.io instance.

## How do I know if my network blocks DNS rebinding?

If your system cannot resolve an address like test-192.168.1.1, your network
provider probably blocks DNS rebinding. Here is an example, note the A record 
is empty while it should show 192.168.1.1.

    $ dig test-192.168.1.1.nip.io
    ; <<>> DiG 9.18.12-0ubuntu0.22.04.3-Ubuntu <<>> test-192.168.1.1.nip.io
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 4542
    ;; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
    
    ;; OPT PSEUDOSECTION:
    ; EDNS: version: 0, flags:; udp: 65494
    ;; QUESTION SECTION:
    ;test-192.168.1.1.nip.io.       IN      A
    
    ;; Query time: 4 msec
    ;; SERVER: 127.0.0.53#53(127.0.0.53) (UDP)
    ;; WHEN: Thu Sep 21 15:26:47 CEST 


## Running a local nip.io instance

Here is how to set up a nip.io instance on your local machine.

Requirements:
* Docker Engine
* systemd-resolved service (installed by default on Ubuntu 18.04 and later)

1. clone the nip.io repo 

       $ git clone https://github.com/exentriquesolutions/nip.io 

2. set the ENV variables in Dockerfile, and run it

        # Dockerfile for nip.io
        ...
        COPY ...
        ENV NIPIO_DOMAIN=nip.io
        ENV NIPIO_NAMESERVERS=ns1.nip.io=127.0.0.52 ns2.nip.io=127.0.0.52
        ENV NIPIO_SOA_NS=ns1.nip.io
        CMD ...

        $ nohup ./build_and_run_docker.sh &

3. add the following to /etc/systemd/resolved.conf

       # Added for resolving nip.io DNS queries 
       [Resolve]
       DNS=127.0.0.52
       Domains=~nip.io

   The `DNS=` IP address must match the `NIPIO_NAMESERVERS` in the Dockerfile.
   This directs the host's DNS service to direct all queries for the nip.io 
   domain to the DNS server running at this IP address (which is your local 
   nip.io instance). See [resolved.conf](https://www.freedesktop.org/software/systemd/man/resolved.conf.html) for details.

4. restart systemd resolved

       $ sudo systemctl restart systemd-resolved.service

5. try dig 

       $ dig foo-192.168.0.1.nip.io

   You should now get the 192.186.0.1 A record
