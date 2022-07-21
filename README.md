# Overview

burpsuite-project-file-parser is a Burp Suite extension to parse project files from the command line and output the results as JSON. It uses the Extender API so it should be cleanly compatible with most versions of Burp. Given a project file this can:

- Print all Audit Items 
- Print all requests/responses from the proxy history
- Print all requests/responses from the site map
- Given a regex search the response headers or response bodies from the proxy history and site map
- Store all requests/responses to a MongoDB

# Blog Posts

[Building an AppSec Pipeline with Burp Suite Data](https://www.silentrobots.com/building-an-appsec-pipeline-with-burpsuite-data/)

[8 Bug Hunting Exampes with burpsuite-project-parser](https://www.silentrobots.com/pushing-burp-suite-data-into-your-testing-pipeline-part-2/)

# Installation

1. Compile the code as described in [Build Information](https://github.com/BuffaloWill/burpsuite-project-file-parser#build-information)
2. Install the extension in Burp
3. **Make sure to set the Output and Errors to system console**

![Set console output](output_to_console.png?raw=true)

4. Close Burp Suite and follow examples below to parse the project file.

# Example Usage

Notes:
- Flags can be combined. For example, print audit items and site map; `auditItems siteMap`; 
  check options below for more information
- `[PATH_TO burpsuite_pro.jar]` is required; my path is: `~/BurpSuitePro/burpsuite_pro.jar` if you need an example. 
- `[PATH TO PROJECT FILE]` requires a project file and it's recommended to give the full path to the project file
- You may need `--add-opens=java.desktop/javax.swing=ALL-UNNAMED --add-opens=java.base/java.lang=ALL-UNNAMED` 
depending on your version of Java

## siteMap and proxyHistory

The siteMap and proxyHistory flags also support sub-components to speed up parsing. They are:

- request.headers
- request.body
- response.headers
- response.body

So, for example, to print out only the request body and headers from proxyHistory you would use:

```bash
java -jar -Djava.awt.headless=true [PATH_TO burpsuite_pro.jar] --project-file=[PATH TO PROJECT FILE] \
  proxyHistory.request.headers, proxyHistory.request.body
```

This massively speeds up parsing as the response bodies (which can be quite large) are ignored.

## Print Audit items

Use the `auditItems` flag, for example:

```bash
java -jar -Djava.awt.headless=true [PATH_TO burpsuite_pro.jar] --project-file=[PATH TO PROJECT FILE] \
  auditItems 
```

## Print site map and proxy history

Combine the `siteMap` and `proxyHistory` flags to dump out all requests/responses from the site map and proxy history:

```bash
java -jar -Djava.awt.headless=true [PATH_TO burpsuite_pro.jar] --project-file=[PATH TO PROJECT FILE] \
    siteMap proxyHistory 
```

## Search Response Headers using Regex

Use the `responseHeader=regex` flag. For example to search for any nginx or Servlet in response header:

```bash
java -jar -Djava.awt.headless=true [PATH_TO burpsuite_pro.jar] --project-file=[PATH TO PROJECT FILE] \
    responseHeader='.*(Servlet|nginx).*'
...
{"url":"https://example.com/something.css","header":"x-powered-by: Servlet/3.0"}
{"url":"https://spocs.getpocket.com:443/spocs","header":"Server: nginx"}
...
```

## Search Response Body using Regex

Note, searching through a response body is memory expensive. It is recommended to store requests/responses in MongoDB and search that. 

Use the `responseBody=regex` flag. For example to search for `<form` elements in response bodies:
```bash
java -jar -Djava.awt.headless=true [PATH_TO burpsuite_pro.jar] --project-file=[PATH TO PROJECT FILE] \
    responseBody='.*<form.*'
```

If you want to clean up the results to something more manageable (rather than the entire response), YMMV with a second grep pattern for the 80 characters around the match:
```bash
java -jar -Djava.awt.headless=true [PATH_TO burpsuite_pro.jar] --project-file=[PATH TO PROJECT FILE] \
  responseBody='.*<form.*'| grep -o -P -- "url\":.{0,100}|.{0,80}<form.{0,80}"
```

## Store the requests/responses to MongoDB

Initialize the collections with a unique index in the db; run the following commands in mongodb:

```bash
use [DATABASE NAME]
db.urls.createIndex({url:1},{unique:true})
db.httpResponses.createIndex({hash:1},{unique:true})
db.httpRequests.createIndex({hash:1},{unique:true})
```

Insert the data into the DB:
```bash
java -jar -Djava.awt.headless=true [PATH_TO burpsuite_pro.jar] --project-file=[PATH TO PROJECT FILE] \
  storeData='localhost:27017/mydb'
```

# Suggestions

- Use a custom User Options file (Burp > User options > Save user options) from Burp Suite with only this extension enabled. This can speed up Burp Suite loading speed because only one extension is loaded. Include the `--user-config-file` flag:
```bash
java -jar -Djava.awt.headless=true [PATH_TO burpsuite_pro.jar] --project-file=[PATH TO PROJECT FILE] --user-config-file=[PATH TO CONFIG FILE]
```

- Set the max amount of memory used by burp with `-Xmx` flag:
```bash
java -jar -Djava.awt.headless=true -Xmx2G [PATH_TO burpsuite_pro.jar] --project-file=[PATH TO PROJECT FILE] 
```

# Build Information

## Option 1:
Run `gradle fatJar` from the root directory. This expects you have gradle and all dependencies installed.

## Option 2:
Build the jar from the Dockerfile.

From the root directory of the project run:
```bash
mkdir build
docker build -t burpsuite-project-file-parser .
docker run --name burpsuite-project-file-parser -v [ADD THE FULLPATH TO YOUR CWD]/build:/tmp burpsuite-project-file-parser
```

The jar file should now be in the build directory of the project.

