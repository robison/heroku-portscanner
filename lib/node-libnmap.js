/*!
 * node-libnmap
 * Copyright(c) 2014 Jason Gerfen <jason.gerfen@gmail.com>
 * License: MIT
 */
var version = 'v0.1.12'
	,	fs = require('fs')
  , xml2js = require('xml2js')
	,	async = require('async')
  , util = require('util')
	,	ipv6 = require('ipv6').v6
	,	proc = require('child_process')
	,	netmask = require('netmask').Netmask
	,	nmap = function(method, options, cb) {

  'use strict';

  /**
   * @object defaults
   * @abstract Default set of options
   *
   * @param {String} nmap - Location of nmap binary
   * @param {String} scripts - Location of nmap lua scripts
   * @param {String} defaults - Default scan options
   * @param {Object} range - Must contain start & end key with value
   * @param {String} ports - Comma separated list of ports to scan
   */
  var defaults = {
    nmap: '/app/bin/nmap',
    scripts: '/app/data/scripts/',
    flags: '--datadir=/app/data -oX -',
    range: '',
    ports: ''
  };

  /**
   * @object methods
   * @abstract Public API
   */
  var methods = methods || {

    /**
     * @function init
     * @abstract Default method (if none called)
     *
     * @param {Object} opts - User supplied options
     *
     * @returns {Object} - Returns help, license & legal info
     */
    init: function(opts) {

      opts = setup.init(opts);

      setup.check(opts);

      return {
        name: 'node-libnmap',
        version: version,
        usage: 'https://github.com/jas-/node-libnmap',
        license: 'https://github.com/jas-/node-libnmap/blob/master/LICENSE',
        issues: 'https://github.com/jas-/node-libnmap/issues',
        nmap: {
          legal: 'http://nmap.org/book/man-legal.html'
        }
      };
    },

    /**
     * @function scan
     * @abstract Performs scan of network device(s)
     *
     * @param {Object} opts - User supplied options
     */
    scan: function(opts, cb) {
      cb = cb || opts;

      opts = setup.init(opts);
      opts.flags = opts.flags + ' -T4';
      setup.verify(opts);
      setup.check(opts);

      var cmd = false
        ,	hosts = tools.convert(opts.range)
        , result = [];

      async.map(hosts, function(host, callback) {
        opts.range = host;
        var xmlOutput = [];
        cmd = tools.command(opts);
        console.log('Starting child process: ' + cmd)
        var e = proc.exec(cmd);

        e.stdout.on('data', function(chunk) {
          if (chunk.length > 0) {
            xmlOutput.push(chunk.trim());
          };
        });

        e.stdout.on('end', function() {
          callback(null, tools.report(xmlOutput));
        });

      }, function(err, results) {
        cb(err, results);
      });
    },
  };

  /**
   * @object setup
   * @abstract Performs initial setup requirements
   */
  var setup = setup || {

    /**
     * @function check
     * @abstract Verifies nmap binary installation
     *
     * @param {Object} opts - User supplied options
     *
     * @returns {Boolean}
     */
    check: function(opts) {
      fs.exists(opts.nmap, function(exists) {
        if (!exists) {
          throw new Error('The nmap binary was not found. Install nmap');
        }
      });
    },

    /**
     * @function init
     * @abstract Initializes application env requirements
     *
     * @param {Object} opts - User supplied options
     */
    init: function(opts) {
      return tools.merge(opts, defaults);
    },

    /**
     * @function verify
     * @abstract Verify options provided
     *
     * @param {Object} opts - User supplied options
     */
    verify: function(opts) {
      if (opts.range) {
        if (!/array|object/.test(typeof (opts.range))) {
          throw new Error('Range must be an array of host(s), examples:' +
            '[192.168.2.10 (single), 10.0.2.0/24 (CIDR), 10.0.10.5-20] (range)');
        }
      }

      if (opts.ports) {
        // Web: http://stackoverflow.com/a/21075138/901697
        if (!/^(?:(?:^|[-,])(?:[1-9][0-9]{0,3}|[1-5][0-9]{4}|6(?:[0-4][0-9]{3}|5(?:[0-4][0-9]{2}|5(?:[0-2][0-9]|3[0-5])))))+$/.test(opts.ports)) {
          throw new Error('Port(s) must match one of the following examples:' +
            '512 (single) | 0-65535 (range) | 22-25,80,443,3306 (multiple)');
        }
      }

      return true;
    }
  };

  /**
   * @object validation
   * @abstract Validation utilities
   */
  var validate = validate || {

    /**
     * @var net
     * @abstract Object with various REGEX patterns to validate network notations
     */
    net: {

      /**
       * @var hostname
       * @abstract Regex for matching hostnames (RFC-1123)
       */
      hostname: /^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$/,

      /**
       * @var IPv4
       * @abstract Regex for matching IPv4 address types
       */
      IPv4: /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/,

      /**
       * @var IPv4CIDR
       * @abstract Regex for matching IPv4 CIDR notation
       */
      IPv4CIDR: /(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([1-2]\d|3[0-2]|\d))/,

      /**
       * @var IPv4Range
       * @abstract Regex for matching IPv4 Range notation
       */
      IPv4Range: /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\-([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/,

      /**
       * @var IPv6
       * @abstract Regex for matching IPv6 address types
       */
      IPv6: /^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*/,

      /**
       * @var IPv6CIDR
       * @abstract Regex for matching IPv6 CIDR notation
       */
      IPv6CIDR: /^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*(\/(\d|\d\d|1[0-1]\d|12[0-8]))$/,
    },

    /**
     * @function perform
     * @abstract Perform user specified regex test on string
     *
     * @param {Object} regex - Regex test case
     * @param {String} str - String to perform test on
     *
     * @returns {Boolean}
     */
    perform: function(regex, str) {
      return regex.test(str);
    },
  };

  /**
   * @object tools
   * @abstract General utilities
   */
  var tools = tools || {

    /**
     * @function command
     * @abstract Generate nmap command string
     *
     * @param {Object} opts - User supplied options
     *
     * @returns {String} NMAP scan string
     */
    command: function(opts) {
      var v6 = new ipv6.Address(opts.range)
      var option = (v6.isValid()) ? ' -6 ' : ' ';

      return (!opts.ports) ?
        opts.nmap + ' ' + opts.flags + option + opts.range :
        opts.nmap + ' ' + opts.flags + option + ' -p' + opts.ports + ' ' + opts.range;
    },

    /**
     * @function convert
     * @abstract Uses validate pattern matching to use/convert hosts array
     * items into blocks in the case of CIDR or range element
     *
     * @param {Array} hosts - Array of hosts, CIDR, hostname, IP or range
     *
     * @returns {Array} Array of network blocks to scan
     */
    convert: function(hosts) {
      var blocks = []
      var results = []
      var cidr = false
      var tests = validate.net;

      hosts.forEach(function(host) {
        switch (true) {
          case (validate.perform(tests.hostname, host) ||
            validate.perform(tests.IPv4, host) ||
            validate.perform(tests.IPv6, host)):

            results.push(host);

            break;
          case (validate.perform(tests.IPv4CIDR, host) ||
            validate.perform(tests.IPv6CIDR, host)):

						/* break up the ipv6 into blocks */

            cidr = new netmask(host);

            blocks = tools.range(cidr);

            blocks.forEach(function(block) {
              results.push(block);
            });

            break;
					case (validate.perform(tests.IPv4Range, host)):

						/* break this up into chunks if possible */

						results.push(host);

						break;
          default:
						/* Silently discard specified host */
            break;
        }
      });

      return results;
    },

    /**
     * @function range
     * @abstract Calculates all possible hosts per CIDR
     *
     * @param {Object} cidr - netmask module object
     *
     * @returns {Array} Each CIDR range split into equal parts
     */
    range: function(cidr) {
      var cpu = require('os').cpus().length
				,	split = cidr.size / cpu
				,	results = [];

      split = (split > 256) ? Math.round(split / 255) : split;

      cidr.forEach(function(ip, long, index) {
        if (index % split === 0) {
          var octets = ip.split('.'),
            start = parseInt(octets[3], 10) - 1,
            end = (start + split) - 1,
            range = octets[0] + '.' + octets[1] + '.' + octets[2] + '.' + start + '-' + end;
          results.push(range);
        }
      });
      return results;
    },

    /**
     * @function calculate
     * @abstract Generates array of ranges based on adapter properties
     *
     * @param {Integer} size - Size of network block
     * @param {Object} range - Start & End IP addresses
     *
     * @returns {Array} Each CIDR   range split into equal parts
     */
    calculate: function(size, range) {
      var cpu = require('os').cpus().length
				,	split = size / cpu
				,	octetsStart = range.start.split('.')
				,	start = parseInt(octetsStart[3])
				,	octetsEnd = range.end.split('.')
				,	end = parseInt(octetsEnd[3])
				,	results = []
				,	str = false;

      octetsStart.pop();
      octetsEnd.pop();

      for (var i = start; i < end; i += split) {
        str = octetsStart[0] + '.' + octetsStart[1] + '.' + octetsStart[2] + '.' + i + '-' +
          ((i + (split - 1) > 256) ? (i + (split - 1)) : (i + (split - 1) - 1));
        results.push(str);
      }
      console.log('node-libnmap.js:483: ' + util.inspect(results));
      return results;
    },

    /**
     * @function merge
     * @abstract Merge/replace default options with user supplied options
     *
     * @param {Object} opts - User supplied options
     * @param {Object} defaults - Default options
     *
     * @returns {Object} Object of a application options
     */
    merge: function(opts, defaults) {
      opts = opts || {};

      for (var item in defaults) {
        if (opts.hasOwnProperty(item))
          defaults[item] = opts[item];

        opts[item] = defaults[item];
      }

      return opts;
    },

    /**
     * @function neighbors
     * @abstract Parse and filter results from nmap scan that are online
     *
     * @param {String} result - NMAP scan results
     *
     * @returns {Array} Array of alive hosts
     */
    neighbors: function(results) {
      var obj = results.split('\n')
        ,	items = [];

      obj.forEach(function(item) {
        if (/status: up/i.test(item)) {
          var host = /Host: (.*)\s\((.*)\).*/g.exec(item);

          if (typeof(host) == 'object')
            items.push((host[2] ? host[2] : host[1]));
        }
      });
      console.log('node-libnmap.js:529: ' + util.inspect(items));
      return items;
    },

    /**
     * @function report
     * @abstract Generates JSON object as report of scan
     *
     * @param {String} results - NMAP scan results
     *
     * @returns {Array} Array of hosts & services
     */
    report: function(xml) {
      var results = {};
      var report = [];
      xml2js.parseString(xml, {
        attrkey: null,
        charkey: null,
        explicitArray: false,
        explicitCharkey: false,
        explicitRoot: false,
        ignoreAttrs: false,
        mergeAttrs: true,
        normalize: true,
        parseBooleans: true,
        parseNumbers: true,
        trim: true,
      }, function(err, results) {
        report.push(results);
      })
      return report;
    },
  };

  /* Robot, do work */
  if (methods[method]) {
    return methods[method].apply(this, Array.prototype.slice.call(arguments, 1));
  } else if ((typeof method === 'object') || (!method)) {
    return methods.init.apply(this);
  } else {
    throw new Error('Method "'+method+'" does not exist, please see node-libnmap API');
  }
};

exports.nmap = nmap;
