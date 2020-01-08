# NIP.IO

[![Build Status](https://travis-ci.org/exentriquesolutions/nip.io.svg?branch=master)](https://travis-ci.org/exentriquesolutions/nip.io)

Dead simple wildcard DNS for any IP Address.

[NIP.IO](http://nip.io) is powered by [PowerDNS](https://powerdns.com) with a simple, 
custom [PipeBackend](https://doc.powerdns.com/authoritative/backends/pipe.html): 
[backend.py](nipio/backend.py)

Head to [NIP.IO](http://nip.io) for more details.

NIP.IO is licensed under [Apache 2.0](LICENSE.txt), and is a free service run by
[Exentrique Solutions](http://exentriquesolutions.com)

## Configuration
`NIPIO_DOMAIN`: NIP.IO main domain.

`NIPIO_TTL`: Default TTL for  NIP.IO backend.

`NIPIO_NONWILD_DEFAULT_IP`: Default IP address for non-wildcard entries.

`NIPIO_SOA_ID`: SOA serial number.

`NIPIO_SOA_HOSTMASTER`: SOA hostmaster email address.

`NIPIO_SOA_NS`: SOA name server.

`NIPIO_NAMESERVERS`: A space seperated list of domain=ip nameserver pairs. Example: `ns1.nip.io=127.0.0.1 ns2.nip.io=127.0.0.1` .

`NIPIO_BLACKLIST`: A space seperated list of description=ip blacklisted pairs. Example: `some_description=10.0.0.1 other_description=10.0.0.2` .