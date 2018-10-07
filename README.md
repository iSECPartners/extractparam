ExtractParam Burp plugin
========

> Released under GPL see LICENSE for more information

## Description
This plugin will extract all the values of the given parameter name within the Burp proxy logs.
Currently looks into:

  * HTTP headers
  * Requests parameters as parsed by Burp (includes GET/POST usual params, cookies, JSon)
  * HTML attributes (i.e. name="`[param name]`" value="`[param value]`")
  * Scripts variable assignement (i.e. param="value")

It creates a consolidated table of all uniques values and their occurences count.
It is possible to export the values list, or the URLs where those value were found or the list of Burp proxy ids for the requests/responses

It also includes some exclusions filters, such as urls in scope, response/requests only, or Content-Type based.

## Usage

* right click in a request/response panel
* select "extract param values"

Note: highlighting the parameter will populate the field value automatically

## Build requirements

* Eclipse IDE
* Burp official application jar file (to be added in the classpath)


