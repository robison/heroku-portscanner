# heroku-portscanner

[![Deploy](https://www.herokucdn.com/deploy/button.png)](https://heroku.com/deploy?template=https://github.com/robison/heroku-portscanner)

usage
=====

request:
====
	curl -L -H 'Content-Type: application/json' -X POST -d '{ "range": [ "8.8.8.0/24" ], "ports": [ "80" ], "flags": "--datadir=/app/data -oX -" }' https://fathomless-journey-1767.herokuapp.com/api/scan/

response:
====
	{ "id": "07504c0a-5d40-4f49-be6b-0f5631a3639f",
	  "url": "https://fathomless-journey-1767.herokuapp.com/api/scan/07504c0a-5d40-4f49-be6b-0f5631a3639f" }

return later to the provided url grab results

"range" can be an array of ranges, CIDR networks, or single hosts
"ports" can be an array or ranges or individual ports
"flags" are extra command-line flags to be passed to nmap