Leek
====

[![Travis Status][travis_img]][travis_url]
[![MIT License][license_img]][license_url]


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
   - [GCC]: Because we use GCC intrinsics and some specific optimizations.

This code targets Linux systems but also works under [Windows Subsystem for Linux] with no noticeable performance drawback.


Compilation & First run
-----------------------

Default compilation produces a re-usable binary that you can transfer to any other Linux system, regardless of the underlying CPU support.

```sh
make
cd src
./leek --help
```

You can also get a slight increase in performances building a machine-specific binary using additional `CFLAGS`.
The generated binary will most likely not work on older machines though.

```sh
make CFLAGS=-march=native
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
	 -t, --threads=#    worker threads count (default is all cores).
	 -I, --impl=#       select implementation (see bellow).
	 -s, --stop(=1)     stop processing after # success (default is infinite).
	 -b, --benchmark    show average speed instead of current speed.
	 -v, --verbose      show verbose run information.
	 -h, --help         show this help and exit.
	
	Available implementations:
		OpenSSL
		SSSE3
		AVX2 (default)

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
   - **Elapsed**: Elapsed time in generation so far with probability to already have a success

The underlying generation process is just a matter of luck and time.

A few performance measurements (in MH/s) on different target CPUs.

| CPU      | Base Freq.  | Thread | OpenSSL |   SSSE3 |    AVX2 |
|----------|-------------|--------|---------|---------|---------|
| i7-7700K | 4.20GHz     | 8      |      47 |     115 |     282 |
| i7-6700  | 3.40GHz     | 8      |      43 |     105 |     254 |
| i5-4690S | 3.20GHz     | 4      |      30 |      90 |     190 |
| i7-4950U | 1.70GHz     | 4      |      13 |      36 |      79 |

All performance measures are taken after an elapsed time of 60 seconds, using the following command:
```sh
./leek --benchmark --prefix leekleek
```
Performances are all measured using any available GCC version, and default compile flags from leek Makefile.
Note that leek uses all CPU cores available by default.


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


FAQ
---

### I try to force-use AVX2 but it keeps crashing with "illegal instruction".

Leek uses the best available implementation by default.
If you want to forcedly a better implementation please make sure that your system does support it (see bellow).

### How do I check whether AVX2 is available on my CPU?

AVX2 instruction set is available since 2014 and Haswell processors (i3/i5/i7 4000 serie).
It is also supported on AMD processors since 2015 and the Excavator family.
Alternatively, you can simply run the following command:
```sh
lscpu | grep avx2
```

### How do I check whether SSSE3 is available on my CPU?

SSSE3 is available on all Intel processors since 2007 and the Core microarchitecture.
When in doubt, feel free to run the following command:
```sh
lscpu | grep ssse3
```

### Will you port it to any Windows/MacOSX?

No, please feel free to use a WSL or any kind of virtual machine.


   [Windows Subsystem for Linux]: <https://msdn.microsoft.com/en-us/commandline/wsl/about>
   [TOR]: <https://www.torproject.org>
   [OpenSSL]: <https://www.openssl.org>
   [Linux]: <https://www.linux.org>
   [GCC]: <https://gcc.gnu.org>
   [eschalot]: <https://github.com/ReclaimYourPrivacy/eschalot>
   [shallot]: <https://github.com/katmagic/Shallot>
   [travis_img]: <https://travis-ci.org/morian/leek.svg?branch=master>
   [travis_url]: <https://travis-ci.org/morian/leek>
   [license_img]: <https://img.shields.io/badge/license-MIT-blue.svg>
   [license_url]: <https://github.com/morian/leek/blob/master/LICENSE>
