apathy
------

Access log PATH analYzer

STATUS
------

**WORK IN PROGRESS**

OVERVIEW
--------

This tool is used to trace HTTP request paths from access logs,
which can be useful when designing load tests or just figuring out
how other people or systems are using a specific web service.

For example, we have the following dummy access log at `examples/simple.log`:

    2018-12-12T12:00:01.000Z 127.0.0.10:5000 127.0.0.1:80 "GET http://my-api/login" "Mozilla/5.0 USERAGENT 1"
    2018-12-12T12:00:02.000Z 127.0.0.20:5000 127.0.0.1:80 "GET http://my-api/login" "Mozilla/5.0 USERAGENT 2"
    2018-12-12T12:00:03.000Z 127.0.0.10:5000 127.0.0.1:80 "GET http://my-api/data" "Mozilla/5.0 USERAGENT 1"
    2018-12-12T12:00:04.000Z 127.0.0.20:5000 127.0.0.1:80 "GET http://my-api/data" "Mozilla/5.0 USERAGENT 2"
    2018-12-12T12:00:05.000Z 127.0.0.10:5000 127.0.0.1:80 "POST http://my-api/data" "Mozilla/5.0 USERAGENT 1"
    2018-12-12T12:00:06.000Z 127.0.0.20:5000 127.0.0.1:80 "DELETE http://my-api/data" "Mozilla/5.0 USERAGENT 2"
    2018-12-12T12:00:07.000Z 127.0.0.30:5000 127.0.0.1:80 "GET http://my-api/login" "Mozilla/5.0 USERAGENT 3"
    2018-12-12T12:00:08.000Z 127.0.0.30:5000 127.0.0.1:80 "GET http://my-api/data" "Mozilla/5.0 USERAGENT 3"
    2018-12-12T12:00:09.000Z 127.0.0.90:5000 127.0.0.1:80 "GET http://my-api/health" "httpkit"

Running the command below...

    $ apathy -o examples/simple.dot examples/simple.log

...would produce the following `dot` -formatted file in `examples/simple.dot`:

    digraph apathy_graph {
        nodesep=1.0;
        ordering=out;
    
        r0 [label="GET http://my-api/login\n(in 33.33% (3), out 33.33% (3))", fontsize=22, penwidth=3.886751];
        r1 [label="GET http://my-api/data\n(in 33.33% (3), out 22.22% (2))", fontsize=20, penwidth=3.357023];
        r2 [label="POST http://my-api/data\n(in 11.11% (1), out 0.00% (0))", fontsize=14, penwidth=1.000000];
        r3 [label="DELETE http://my-api/data\n(in 11.11% (1), out 0.00% (0))", fontsize=14, penwidth=1.000000];
        r4 [label="GET http://my-api/health\n(in 11.11% (1), out 0.00% (0))", fontsize=14, penwidth=1.000000];

        r0 -> r1 [xlabel="33.33% (3)", fontsize=22, penwidth=3.886751];
        r1 -> r3 [xlabel="11.11% (1)", fontsize=18, penwidth=2.666667];
        r1 -> r2 [xlabel="11.11% (1)", fontsize=18, penwidth=2.666667];
    }

Now we can, for example, use the `graphviz` tool to transform it into a PNG image:

    $ sfdp -x -Goverlap=scale -Tpng examples/simple.dot -o examples/simple.png

![alt text](examples/simple.png)

From the image we can observe the following facts:

  * `GET http://my-api/login` was called 3 times, and each session
    made another 3 calls after that.
  * `GET http://my-api/data` was called 3 times, but only 2 sessions
    made any other requests after that.
  * `POST http://my-api/data` and `DELETE http://my-api/data` were both called
    only once, and no requests were made after that during any sessions.
  * `GET http://my-api/health` has been called once without a follow-up,
    so it's probably from a monitoring service.

### What is a session?

A session is meant to identify a single user or system during the
lifetime of a log file, consisting of the source IP address and user agent
string by default.


USAGE
-----

The program expects that any log files fed to it contain
at least the following fields:

  * RFC3339-formatted timestamp with millisecond precision.
    - example: `2018-01-01T12:30:00.400`
  * Request field, surrounded by double quotes, with the method and URL inside.
    - example: `"GET https://my-api/v1/data?limit=50 HTTP/1.0"`

Additionally, at least one of the following fields must be present,
in order to identify meaningul session information:

  * Source IPv4 address, with or without a port number.
    - examples: `127.0.0.1:5000` or `10.1.1.50`
  * User agent string, surrounded by double quotes.
    - example: `"Mozilla 5.0 ..."`


TODO
----

  * ignore patterns
  * IPv6 source and destination addresses
  * tests
  * non-surrounded request fields
