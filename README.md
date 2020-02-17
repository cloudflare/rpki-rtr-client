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
There's a data directory created with JSON files of every serial numbers worth of ROA data. The directory is sorted by `YYYY-MM` and the files include the full date (in UTC).
```
   $ ls -lt data/
   total 0
   drwxr-xr-x  7 martin martin  224 Feb 11 09:36 2020-02
   $

   $ ls -lt data/2020-02
   total 21592
   -rw-r--r--  1 martin martin  5520676 Feb 16 18:22 2020-02-17-022209.routes.00000365.json
   -rw-r--r--  1 martin martin  5520676 Feb 16 18:42 2020-02-17-024242.routes.00000838.json
   -rw-r--r--  1 martin martin      412 Feb 16 19:56 2020-02-17-035645.routes.00000841.json
   -rw-r--r--  1 martin martin      272 Feb 16 20:16 2020-02-17-041647.routes.00000842.json
   -rw-r--r--  1 martin martin      643 Feb 16 20:36 2020-02-17-043649.routes.00000843.json
   $
```
## CHANGELOG
 - This is the first release and while it works, it is not ready for prime time
 - Directory format updated to split by YYYY-MM in case it gets big (plus the serial number may not be sequential)

