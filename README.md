# rpki-rtr-client
## INTRODUCTION
A simple client-side implementation of the RTR [RFC8210](https://tools.ietf.org/html/rfc8210) protocol in Python
## INSTALL
Presently the code is easiest to install via github.
```
   $ pip3 install netaddr
   ...
   $

   $ git clone https://github.com/cloudflare/rpki-rtr-client.git
   ...
   $ cd rpki-rtr-client
   $
```
## USAGE
Cloudflare provides an open RTR server at `rtr.rpki.cloudflare.com` port `8282`.
```
   $ ./rtr_client.py -h rtr.rpki.cloudflare.com -p 8282
   ...
   ^C
   $
```
There's a data directory created with JSON files of every serial numbers worth of ROA data
```
   $ ls -lt data/
   total 116392
   -rw-r--r--  1 martin martin  5538933 Feb 11 11:25 routes.00000606.json
   -rw-r--r--  1 martin martin     1231 Feb 11 10:27 routes.00000599.json
   -rw-r--r--  1 martin martin      123 Feb 11 10:06 routes.00000598.json
   -rw-r--r--  1 martin martin  5537071 Feb 11 09:26 routes.00000597.json
   $
```
## CHANGELOG
 - This is the first release and while it works, it is not ready for prime time

