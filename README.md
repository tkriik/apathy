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
    2018-12-12T12:00:01.500Z 127.0.0.90:5000 127.0.0.1:80 "GET http://my-api/health" "httpkit"
    2018-12-12T12:00:02.000Z 127.0.0.20:5000 127.0.0.1:80 "GET http://my-api/login" "Mozilla/5.0 USERAGENT 2"
    2018-12-12T12:00:03.000Z 127.0.0.10:5000 127.0.0.1:80 "GET http://my-api/data" "Mozilla/5.0 USERAGENT 1"
    2018-12-12T12:00:04.000Z 127.0.0.20:5000 127.0.0.1:80 "GET http://my-api/data" "Mozilla/5.0 USERAGENT 2"
    2018-12-12T12:00:05.000Z 127.0.0.10:5000 127.0.0.1:80 "POST http://my-api/data" "Mozilla/5.0 USERAGENT 1"
    2018-12-12T12:00:05.250Z 127.0.0.10:5000 127.0.0.1:80 "GET http://my-api/login" "Mozilla/5.0 USERAGENT 1"
    2018-12-12T12:00:05.500Z 127.0.0.90:5000 127.0.0.1:80 "GET http://my-api/health" "httpkit"
    2018-12-12T12:00:06.000Z 127.0.0.20:5000 127.0.0.1:80 "DELETE http://my-api/data" "Mozilla/5.0 USERAGENT 2"
    2018-12-12T12:00:07.000Z 127.0.0.30:5000 127.0.0.1:80 "GET http://my-api/login" "Mozilla/5.0 USERAGENT 3"
    2018-12-12T12:00:08.000Z 127.0.0.30:5000 127.0.0.1:80 "GET http://my-api/data" "Mozilla/5.0 USERAGENT 3"
    2018-12-12T12:00:09.000Z 127.0.0.90:5000 127.0.0.1:80 "GET http://my-api/health" "httpkit"

Running the command below...

    $ ./apathy -o examples/simple.dot examples/simple.log

...would produce the following `dot` -formatted file in `examples/simple.dot`:

    digraph apathy_graph {
        nodesep=1.0;
        rankdir=LR;
        ranksep=1.0;
    
        subgraph s0 {
            rank = same;
            r0 [label="GET http://my-api/login\n(in 33.33% (4), out 25.00% (3), min_depth = 1)", fontsize=28, style=filled, fillcolor="#e2aaae", penwidth=4.000000];
            r1 [label="GET http://my-api/health\n(in 25.00% (3), out 16.67% (2), min_depth = 1)", fontsize=25, style=filled, fillcolor="#d3c5eb", penwidth=3.632993];
        }
    
        subgraph s1 {
            rank = same;
            r2 [label="GET http://my-api/data\n(in 25.00% (3), out 16.67% (2), min_depth = 2)", fontsize=25, style=filled, fillcolor="#a6ffb9", penwidth=3.632993];
        }
    
        subgraph s2 {
            rank = same;
            r3 [label="POST http://my-api/data\n(in 8.33% (1), out 8.33% (1), min_depth = 3)", fontsize=22, style=filled, fillcolor="#c6e5e9", penwidth=3.154701];
            r4 [label="DELETE http://my-api/data\n(in 8.33% (1), out 0.00% (0), min_depth = 3)", fontsize=14, style=filled, fillcolor="#9180b2", penwidth=2.000000];
        }
    
        r0 -> r2 [xlabel="25.00% (3)", fontsize=28, style="solid", color="#b4888b", fontcolor="#876668", penwidth=4.000000];
        r1 -> r1 [xlabel="16.67% (2)", fontsize=25, style="dotted", color="#a89dbc", fontcolor="#7e768d", penwidth=3.632993];
        r2 -> r4 [xlabel="8.33% (1)", fontsize=22, style="solid", color="#84cc94", fontcolor="#63996f", penwidth=3.154701];
        r2 -> r3 [xlabel="8.33% (1)", fontsize=22, style="solid", color="#84cc94", fontcolor="#63996f", penwidth=3.154701];
        r3 -> r0 [xlabel="8.33% (1)", fontsize=22, style="dashed", color="#9eb7ba", fontcolor="#76898b", penwidth=3.154701];
    }

Now we can, for example, use the `dot` tool from `graphviz`
to transform it into a PNG image:

    $ dot -Tpng examples/simple.dot -o examples/simple.png

![alt text](examples/simple.png)

From the image we can observe at least the following facts:

  * The most common call path is from `GET http://my-api/login` to
    `GET http://my-api/data`, as that edge was taken 3 times.
  * Less common edges are from `GET http://my-api/data` to 
    `POST http://my-api/data` and `DELETE http://my-api/data`,
    and from `POST http://my-api/data` back to `GET http://my-api/login`.
  * `GET http://my-api/health` has been called 3 times, consisting of 2
    repeats, so it's probably from a monitoring service.

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
