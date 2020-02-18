Leek
====

[![MIT License][license_img]][license_url]


About
-----
Leek is another tool to generate custom .onion addresses for [TOR] [hidden services](https://www.torproject.org/docs/hidden-services).
This program leverages vector instructions sets (_SSSE3_ / _AVX2_ / _AVX512_) to compute 4, 8 or 16 addresses in parallel.
First-generation .onion address generation heavily relies on SHA1 hashes, that's why Leek also uses a redesigned version of SHA1.

Search features include:
   - Fixed-prefix lookup
   - Dictionary based lookup

There is no regex based lookup as you might find in eschalot, mostly because of the lack of interest.

Special thanks and references:
   - Some of the software architecture is inspired by [eschalot] (itself forked from [shallot])
   - Original SHA1 vectorized implementation was provided by a friend and partially reworked
   - [Intel Intrinsics Guide]
   - [AVX512 Ternary functions] by [0x80.pl]


Requirements
------------
   - [OpenSSL]: For RSA generation and SHA1 rechecks (`libssl-dev` on Debian)
   - [GCC] or [CLANG]: Works on both with any decent version.
   - [Autotools] for build system (autoconf, automake, etc...)

This code targets Linux systems but also works under [Windows Subsystem for Linux] with no noticeable performance drawback.



Compilation & First run
-----------------------

Default compilation produces a re-usable binary that you can transfer to any other Linux system, regardless of the underlying CPU support.

```sh
bash autogen.sh
./configure
make
./leek --help
```


Package building
----------------

### Centos

Centos package build procedure also probably works on Fedora or RedHat but has not been tested on these distributions (only Centos7 and Centos8).
You obviously need to install the required dependencies (OpenSSL, autotools, make, etc...) and any package that provides `rpmbuild` (generally `rpm-build`).

```sh
bash autogen.sh
./configure
make rpm
```

You can then install these packages using `yum` or `dnf`, they are located in `_build/RPMS/x86_64/`.


### Debian

Debian package build procedure has been tested on Debian10 but would probably also work on other debian forks.
Before you can build the debian package make sure to install all required tools such as `devscripts`, `lintian`, `build-essential`, `pkg-config`.

```sh
bash autogen.sh
./configure
make deb
```


Options
-------
	Usage: ./leek [OPTIONS]
	
	 -p, --prefix       single prefix attack.
	 -i, --input        input dictionary with prefixes.
	 -o, --output       output directory (default prints on stdout).
	 -l, --length=N:M   length filter for dictionary attack [4-16].
	 -d, --duration     how long to run (in seconds, default is infinite).
	 -t, --threads=#    worker threads count (default is all cores).
	 -I, --impl=#       select implementation (see bellow).
	 -s, --stop(=1)     stop processing after # success (default is infinite).
	 -v, --verbose      show verbose run information.
	 -h, --help         show this help and exit.
	     --no-results   do not display live results on stdout.
	
	Available implementations:
	  OpenSSL
	  UINT32
	  SSSE3
	  AVX2 (default)
	  AVX512

Usage
-----
Simple prefix lookup is something like this:

```sh
./leek --verbose --prefix gitleek
```

Result on `stdout` (after a few minutes) would look as follow:
```
[+] Loaded 1 valid prefixes with size 7.
[+] Using AVX2 implementation on 4 worker threads.
> gitleekb5tmg7kkw.onion (len:7, e:0x543008c5 (10), id=0)
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQC9En/ra+U5LHOJSzsNLZbsDGvZxyaWPSBQ7qfhIpkGdbcrj/tt
uwdeMAsweoCLtwMQjFBp3/HaZZxFtKbv84TXL3sALKowN7HukVPp2VNPU30+E2lt
59F8ZhivWoSXy+LfPjBIeXsyrF9i6xlkhiNj6LnQTf+QOmgXmevWmvvkZwIEVDAI
xQKBgDTb+uDjY+6N8W1dIxc5SEJNfBEgYpa13R+0e/8fzz7PBxFUyFYhBIe6gmu0
211V7KVSSGm0HrBVL4A5PxqpsYHMPCpSvHFRyXUDIQFDKoRX0ezrtFeOkuSU5z9s
o7PgljJx6zxr7mA1BnZWHxmTk0qWYKnwxT4+8hY95p7GTN3RAkEA+YG1AX9Ue9ki
8v83zEvGMDuq+acyJhD/8eLOp0MYQk4rEfAKRSxdk5G888zjG0v8/KE5xpAi7WC0
kylaG1HJ+wJBAMH+KMyf04b8mTdNeLSHdT0VxlJ1yzdOxR5cEQwDAX6TTDMdHxOm
Bz2N/b8lWjWGoBKZNPBqjnUOmDocO3nEz4UCQQDPaH0UcLQvQ3801x+xMLCrxAQq
whrkg2AoziuwHsbgp3dTMGNaHWLkCslmqsSkU4SJihHkiNoYJur4JUXXOdknAkAn
l8qe3ann3HjvuFESV7eo2faz5YRMayKl1kVLGQkrBA4px1Xblm6wYQ5890vZzgFW
+h1zYvWLT5uej+gTw7hNAkEAyh0aypskUpYOW4lqETyPW0u0XivHV87uGIXQq9r7
GmOUJm9URoBVbo9fUVvtoxZ6ZBQVa6gGKtHNQm2Zhll9Rg==
-----END RSA PRIVATE KEY-----

[h]elp [s]tatus [f]ound [q]uit =>
```

Put the RSA private key in a file called `private_key` in the `HiddenServiceDir` as specified in your torrc, then restart your service.
A `hostname` file will be created in `HiddenServiceDir` containing your new .onion address.


Security
--------
All generated RSA keypairs are checked using standard OpenSSL methods.
The only drawback I see from this way of generating .onion addresses is the unusual size of the public exponent e.
This unusual size makes it obvious that you used Leek or any other similar software for .onion address generation.


Performance
-----------
Leek provides a few metrics during the generation (using 's'):
   - **Hashs**: Total number of checked candidates
   - **Rate**: Generation speed in Hash per second (candidate/s)
   - **Tavg**: Average time between two results at current rate
   - **Percent**: Success probabilities so far
   - **Elapsed**: Elapsed time in generation so far

The underlying generation process is just a matter of luck and time.

A few performance measurements (in MH/s) on different target CPUs.

| CPU           | Base Freq.  | Core/Thread | OpenSSL |   SSSE3 |    AVX2 |  AVX512 |
|---------------|-------------|-------------|---------|---------|---------|---------|
| Ryzen 9 3900X |     3.80GHz |      12/24  |     130 |     325 |     617 |     N/A |
|    Xeon 8124M |     3.00GHz |       8/16  |      47 |     165 |     365 |     850 |
|      i7-7700K |     4.20GHz |        4/8  |      47 |     115 |     280 |     N/A |
|      i5-4690S |     3.20GHz |        4/4  |      30 |      90 |     190 |     N/A |
|      i7-4950U |     1.70GHz |        2/4  |      13 |      36 |      79 |     N/A |
|       i7-6700 |     3.40GHz |        4/8  |      43 |     105 |     255 |     N/A |

All performance measures are taken after an elapsed time of 60 seconds, using the following command:
```sh
./leek --duration 60 --no-result --prefix leekleek
```
Performances are all measured using any available GCC version with default compile flags from Makefile.
Leek uses all available logical cores by default.

Coarse average time to generate a .onion with a given prefix length on a 150MH/s configuration:

| len(prefix) |          Time |
|-------------|---------------|
| 4           |         00:00 |
| 5           |         00:00 |
| 6           |         00:06 |
| 7           |         03:15 |
| 8           |      01:44:00 |
| 9           |    2:08:00:00 |
| 10          |   74:21:00:00 |
| 11          | 2365:00:00:00 |

Every additional character multiplies the required time by 32 for a fixed number of prefixes.


FAQ
---

### I try to force-use AVX2/AVX512 but it keeps crashing with "illegal instruction".

Leek uses the best implementation available on your system (by default).
If you want to forcedly a more efficient implementation please make sure that your system has support for it (see bellow).

### How do I check whether AVX512 is available on my CPU?

AVX512-BW instruction set is available since 2017 and Skylake-SP Skylake-X CPUs.
This means that this is now available only on very high-end desktop and high-end server computers.
To check compatibility please run the following command:
```sh
grep avx512bw /proc/cpuinfo
```

### How do I check whether AVX2 is available on my CPU?

AVX2 instruction set is available since 2014 and Haswell processors (i3/i5/i7 4000 serie).
It is also supported on AMD processors since 2015 and the Excavator family.
To check compatibility please run the following command:
```sh
grep avx2 /proc/cpuinfo
```

### How do I check whether SSSE3 is available on my CPU?

SSSE3 is available on all Intel processors since 2007 and the Core microarchitecture.
To check compatibility please run the following command:
```sh
grep ssse3 /proc/cpuinfo
```

### Will you port it to any Windows/MacOSX?

No, please feel free to use a WSL or any kind of virtual machine.


   [Windows Subsystem for Linux]: <https://msdn.microsoft.com/en-us/commandline/wsl/about>
   [TOR]: <https://www.torproject.org>
   [OpenSSL]: <https://www.openssl.org>
   [Autotools]: <https://www.gnu.org/software/automake/manual/html_node/Autotools-Introduction.html>
   [Linux]: <https://www.linux.org>
   [GCC]: <https://gcc.gnu.org>
   [CLANG]: <https://clang.llvm.org/>
   [eschalot]: <https://github.com/ReclaimYourPrivacy/eschalot>
   [shallot]: <https://github.com/katmagic/Shallot>
   [license_img]: <https://img.shields.io/badge/license-MIT-blue.svg>
   [license_url]: <https://github.com/morian/leek/blob/master/LICENSE>
   [AVX512 Ternary functions]: <http://0x80.pl/articles/avx512-ternary-functions.html>
   [Intel Intrinsics Guide]: <https://software.intel.com/sites/landingpage/IntrinsicsGuide/>
   [0x80.pl]: <http://0x80.pl>
