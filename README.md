QuantifiedNet: a minimal tracer of network connections
======================================================

QuantifiedNet is a simple Linux application that tracks TCP connection using
[libpcap](http://www.tcpdump.org/). For each connection it keeps track of:

* local IP and port;
* remote IP and port;
* data sent;
* data received;
* connection start time;
* connection end time.

All data is stored in a SQLite3 database.


Dependencies
------------
* [libpcap](http://www.tcpdump.org/)
* [SQLite3](http://www.sqlite.org/)
* [cmake](http://www.cmake.org/)

On Debian/Ubuntu:

```
apt-get install libpcap-dev libsqlite3-dev
```


Compilation
-----------
```
cmake .
make
```

Usage
-----

```
Usage: quantifiednet [OPTION...] INTERFACE DB
quantifiednet -- a minimal tracer of network connections

  DB                         Path to SQLite database
  INTERFACE                  Interface to listen on (e.g., eth0, any to listen
                             on all available interfaces)
  -v, --verbose              Produce verbose output
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version
```


SQLite3 schema
--------------

Table `tcp_connections`:

* id integer primary key
* locip text not null
* locport integer not null
* remip text not null
* remport integer not null
* sent integer not null
* rcvd integer not null
* starttime text not null
* endtime text not null
* durationmsec integer not null

Dates are stored in the `YYYY-MM-DD HH:MM:SS.SSS` format and can be accessed using SQLite date and time functions. For more information please refer to [SQLite documentation](http://www.sqlite.org/lang_datefunc.html).


Todo
----
* Add support for UDP connections
* Support half-opened TCP connections
