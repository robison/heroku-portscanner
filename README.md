# heroku-portscanner

[![Deploy](https://www.herokucdn.com/deploy/button.png)](https://heroku.com/deploy?template=https://github.com/robison/heroku-portscanner)

usage
=====
request:

POST /api/scan HTTP/1.1
Host: fathomless-journey-1767.herokuapp.com
Content-Type: application/json
Cache-Control: no-cache

{ "range": [ "8.8.8.0/24" ], "ports": [ "80" ], "flags": "--datadir=/app/data -oX -" }

response:

{
    "id": "07504c0a-5d40-4f49-be6b-0f5631a3639f",
    "url": "https://<hostname>.herokuapp.com/api/scan/07504c0a-5d40-4f49-be6b-0f5631a3639f"
}


return later to the provided url grab results