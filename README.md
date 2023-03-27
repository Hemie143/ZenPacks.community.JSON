Goal
----
Monitor a JSON object reported by a web server.

This ZenPack provides only two datasources to be used in different business/technical cases:

 - RESTMonitorValue - This allows you to compare a JSON value to a list of values and trigger an event whether the found value is found in the list (or not). 
 - RESTMonitorNumeric - This allows you to import a JSON value into a metric and display it in a graph.

Protocol
--------
HTTP / HTTPS

Releases
--------

 - 1.0.0 (27/03/2023) : First release

Bugs
----
nihil

Next features
-------------
 - Nicer dialog box for datasources, as properties are not presented in a logical and clear order. 
 - Testable datasource within dialog box. Ability to read output. 
 - Add payload in HTTP request.

Notes
-----
This ZenPack is using the jsonpath_ng library, which allows you to define a path to the desired value within a JSON object. 
The syntax is defined here: https://github.com/h2non/jsonpath-ng
