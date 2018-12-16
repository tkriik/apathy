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

For example, supposed you had an access log with following lines
in a file named `my_access.log`:

    2018-12-12T12:00:01.000Z 127.0.0.10:5000 127.0.0.1:80 "GET http://my-api/login" "Mozilla/5.0 USERAGENT 1"
    2018-12-12T12:00:02.000Z 127.0.0.20:5000 127.0.0.1:80 "GET http://my-api/login" "Mozilla/5.0 USERAGENT 2"
    2018-12-12T12:00:03.000Z 127.0.0.10:5000 127.0.0.1:80 "GET http://my-api/data" "Mozilla/5.0 USERAGENT 1"
    2018-12-12T12:00:04.000Z 127.0.0.20:5000 127.0.0.1:80 "GET http://my-api/data" "Mozilla/5.0 USERAGENT 2"
    2018-12-12T12:00:05.000Z 127.0.0.10:5000 127.0.0.1:80 "POST http://my-api/data" "Mozilla/5.0 USERAGENT 1"
    2018-12-12T12:00:06.000Z 127.0.0.20:5000 127.0.0.1:80 "DELETE http://my-api/data" "Mozilla/5.0 USERAGENT 2"
    2018-12-12T12:00:07.000Z 127.0.0.30:5000 127.0.0.1:80 "GET http://my-api/login" "Mozilla/5.0 USERAGENT 3"
    2018-12-12T12:00:08.000Z 127.0.0.30:5000 127.0.0.1:80 "GET http://my-api/data" "Mozilla/5.0 USERAGENT 3"

Running the command below...

    $ apathy my_access.log

...would produce the following output:

    ---
    unique_sessions: 3
    shared_paths: 2
    paths:
        - 1:
            - starts: 2
            - requests:
                - GET http://my-api/login
                    - hits: 2
                - GET http://my-api/data
                    - hits: 2
                - DELETE http://my-api/data
                    - hits: 1
        - 2:
            - starts: 1
            - requests:
                - GET http://my-api/login
                    - hits: 1
                - GET http://my-api/data
                    - hits: 1
                - POST http://my-api/data
                    - hits: 1
    ...

Analyzing the output, we find the following features:

    unique_sessions: 3
    ...

This tells us that there are three unique *sessions* during the span
of the log, which is identified by the source IP address and user agent
by default.

    ...
    shared_paths: 2
    ...

Although there are three sessions, there are only two shared paths
taken by those sessions.

    ...
    paths:
        - 1:
	    ...
        - 2:
	    ...
    ...

The path listing shows all paths taken, ranked by how many times
each path was started.

    ...
        - 1:
            - starts: 2
            - requests:
                - GET http://my-api/login
                    - hits: 2
                - GET http://my-api/data
                    - hits: 2
                - DELETE http://my-api/data
                    - hits: 1
    ...

Here we see that the first path was started 2 times.
The `hits` field tells how many started paths ended up
at that request, so while both paths went through the first
two requests, only one of them ended up at the third request.


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

  * deterministic multithreading
  * ignore patterns
  * truncate patterns
  * merge patterns
  * IPv6 source and destination addresses
  * tests
  * non-surrounded request fields
