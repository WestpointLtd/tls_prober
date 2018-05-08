# TLS Prober

TLS Prober is a tool for identifying the implementation in use by SSL/TLS
servers. It analyses the behaviour of a server by sending a range of probes
then comparing the responses with a database of known signatures. Key features
include:

 * Requires no knowledge of the server configuration.

 * Does not rely on the supported cipher suites (since administrators often
   change those).

 * Successfully identifies openssl, schannel, Java (JSSE), wolfSSL (previously
   CyaSSL), GnuTLS, MatrixSSL, mbedTLS (previously PolarSSL).

 * Supports both pure SSL/TLS protocols like HTTPS and those that use STARTTLS
   such as SMTP and POP3.

 * Reslient against differences in the build options used by a given server.

 * Extensible - you can easily record the signatures of additional
   implementations.

# Installation

Clone the repository and the pytls submodule then run it!

```
git clone https://github.com/WestpointLtd/tls_prober.git
cd tls_prober/ && git submodule update --init
```

TLS Prober requires python and has been tested using python 2.7, it is
possible it may work with earlier versions too.

Note that the current implementation will not work on Windows since it makes
use of the select() system call which is not available on that platform.

## Basic Usage

Using TLS Prober is as easy as:

```
./prober.py www.google.com
```

The output is a sorted list of matches with the best match first, for example
the command above resulted in:

```
openssl-1.0.1h default source build     15
openssl-1.0.1h default source build (no-ec)     15
openssl-1.0.1g default source build     14
openssl-1.0.1g default source build (no-ec)     14
...
```

# Common Options

The most commonly used option is *-p* which allows you to specify an
alternative port (the default is 443). You can also use *-s* to select a
STARTTLS mode, however generally the default mode of 'auto' will do the right
thing.

TLS Prober supports operation over a socks proxy (for example the one provided
by SSH). To use this feature you must set the *socks_proxy* environment
variable, for example:

```
export socks_proxy=localhost:1080
```

# Adding a Signature

Adding a new signature is easy, simply run TLS Prober like this:

```
./prober.py -a 'ACME TLS version 1.0.0' www.example.com
```

This will probe the server and add it to the fingerprint database. Please
submit new fingerprints back so that they can be included in future releases.

# Implementation

For details of the implementation see the [included paper](doc/tls_prober.md)
in the doc directory.

# Author

TLS Prober was written by Richard Moore <rich@kde.org>.

# Credits

Thanks to my colleagues at Westpoint for comments and suggestions,
particularly Simon Ward. Thanks also to Daniel Molkentin and Peter Hartmann
for providing feedback.

