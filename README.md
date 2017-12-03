Leek
====

About
-----
Leek is another tool to generate custom .onion addresses for [TOR] [hidden services](https://www.torproject.org/docs/hidden-services).
This program leverages vector instructions sets (_SSSE3_ / _AVX2_) to compute 4 or 8 addresses at the same time.
First-generation .onion address generation heavily relies on SHA1 hashes, that's why Leek also uses a redesigned version of SHA1.

Search features include:
   - Fixed-prefix lookup
   - Dictionary based lookup

There is no regex based lookup as you might find in eschalot, mostly because of the lack of interest.

Some special thanks:
   - Leek software architecture is inspired by [eschalot] (itself forked from [shallot])
   - Original SHA1 vectorized implementation was provided by a friend and partially reworked


Requirements
------------
   - [OpenSSL]: For RSA generation and SHA1 rechecks (`libssl-dev` on Debian)
   - [GCC]: Because we use GCC intrinsics

This code targets Linux systems but also works under [Windows Subsystem for Linux] with no noticeable performance drawback.


Compilation & First run
-----------------------
```sh
make
cd src
./leek --help
```

Options
-------
	Usage: ./leek [OPTIONS]
	
	 -p, --prefix       single prefix attack.
	 -i, --input        input dictionary with prefixes.
	 -o, --output       output directory (default prints on stdout).
	 -l, --length=N:M   length filter for dictionary attack [4-16].
	 -t, --threads=#    worker threads count (default is 1).
	 -s, --stop(=1)     stop processing after # success (default is infinite).
	 -b, --benchmark    show average speed instead of current speed.
	 -v, --verbose      show verbose run information.
	 -h, --help         show this help and exit.

Usage
-----
Simple prefix lookup is something like this:

```sh
./leek --prefix gitleek
```

Result on `stdout` (after a few minutes) would look as follow:
```
[|] Speed: 60.7MH/s   Total: 12.07GH   T(avg): 0:00:06:39   Elapsed: 0:00:03:22 ( 29.63%)
[+] Found gitleekymhxsnt4w.onion (size=7, popcnt(e)=14, ID=1)
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCxL752NLsBvLohiEauylMYVlK5MMpCQS646j5pUuGNh5UTti7H
WLlx/axbOPsRs1qHBvXGw347JndExzrSjUMHjgnARLkUF13AC5t9qzRXITw+mHxJ
7ynlkiLu1DrCxNl1/sXjiMPcSTZ0t41gAKYPGLxy7vBeQPBCleaMQZJH0QIEYSY2
SwKBgASBfBZYqboZbk4ad2BVCPOdiF+rGeglM18w5EBstuknMGDy2MzJcIcaBOJM
8uwPcONh1Y2h6r9M9biQiUgcE+XG/H290yA0Q/2P34DAZfzVjxj245ceCZGT/QoQ
3rhMZi3IplGrJyj1cHrbJmg37xxvIC6hJWjtAsapIvCpPZtTAkEA5wZA1/RlJzbi
iGfi258GP2tbeEmkrd/8AQ/FmySYsqXOusGv8MqevWKEqh8bLOwr1hqVuaIPpwmM
aW1Ef//gGQJBAMRXfftKuLFUOrFAWBBmsp/bydZkSxLmIic0cBM/OLZI1MJoSQKj
x9RlNE3Qj12/BdBEa88TODXF/dE32AdnvHkCQQDB3xbTu/MhVjghmoCZ/jLXJ/F1
6fXDGmvs3bl3pDHSbUnDM9TcqM7ni0TPRKZ/7003UW9L0hiNQUR8KID8P0Z7AkA6
Vkyh0vRcxDZD4e4mBry3xsl1vKIhVvL4gPKHqka1Zfk6WfQJahCXKMFhhk3BVioM
dPjsUndkcLwwNiqhtdZLAkAoXJ3elHG1qGTaKNQ17qn92IMnL6QjLExTyIeUJTih
BnXkADelnNQx/+MLw56x/16dMEO4YXIMgeF63gBTY2D3
-----END RSA PRIVATE KEY-----
```

Put the RSA private key in a file called `private_key` in the `HiddenServiceDir` as specified in your torrc, then restart your service.
A `hostname` file will be created in `HiddenServiceDir` containing your new .onion address.


Security
--------
All generated RSA keypairs are checked using standard OpenSSL methods.
The only drawback I see from this way of generating .onion addresses is the unusual size of the public exponent e.
This unusual size makes it obvious that you used Leek or any other similar software for .onion address generation.
It also introduces a minor performance overhead for all exchanges between you and the .onion clients connecting to your server.
The bigger **popcnt(e)**, the longer it takes to establish a connection with your server.


Performance
-----------
Leek provides a few metrics during the generation:
   - **Speed**: Generation speed in Hash per second (candidate/s)
   - **Total**: Number of checked candidates
   - **T(avg)**: Estimated time to reach a 50% success probability
   - **Elapsed**: Elapsed time in generation so far

The underlying generation process is just a matter of luck and time.

A few performance measurements on different target CPUs:

| CPU      | Base Freq.  | Impl.  | Thread | Performance |
|----------|-------------|--------|--------|-------------|
| i7-7700K | 4.20GHz     | AVX2   | 8      | 275MH/s     |
| i7-6700  | 3.40GHz     | AVX2   | 8      | 238MH/s     |
| i5-4690S | 3.20GHz     | AVX2   | 4      | 200MH/s     |
| i7-4950U | 1.70GHz     | AVX2   | 4      |  79MH/s     |

All performance measures are taken after an elapsed time of 2 minutes, using the following command:
```sh
./leek --benchmark --prefix leekleek --threads=X
```
Where `X` is the number of logical cores on the considered CPU.


Coarse average time (50% chances) to generate a .onion with a given prefix length on a 150MH/s configuration:

| len(prefix) | Time          |
|-------------|---------------|
| 4           | instant       |
| 5           | instant       |
| 6           | 4 seconds     |
| 7           | 2 minutes     |
| 8           | 1 hour        |
| 9           | 2 days        |
| 10          | 55 days       |
| 11          | 5 years       |
| 12          | 155 years     |

   [Windows Subsystem for Linux]: <https://msdn.microsoft.com/en-us/commandline/wsl/about>
   [TOR]: <https://www.torproject.org>
   [OpenSSL]: <https://www.openssl.org>
   [Linux]: <https://www.linux.org>
   [GCC]: <https://gcc.gnu.org>
   [eschalot]: <https://github.com/ReclaimYourPrivacy/eschalot>
   [shallot]: <https://github.com/katmagic/Shallot>
