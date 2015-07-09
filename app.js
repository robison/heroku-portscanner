// App.js
// Call the packages we need

var util       = require('util');               // Util for inspecting objs
var express    = require('express');            // Call express
var app        = express();                     // Define our app using express
var bodyParser = require('body-parser');        // Get params from body of HTTP
var scanner    = require('./lib/node-libnmap'); // Nmap interaction
var mongoose   = require('mongoose');           // Mongolab interaction
var Scan       = require('./models/scan');      // Mongoose model
var port       = process.env.PORT || 8080;      // Set our port

// Connect to the Mongolab instance
mongoose.connect(process.env.MONGOLAB_URI);

// Get an instance of the router
var router = express.Router();

// Configure app to use 2 spaces when printing JSON
app.set('json spaces', 2);

// Configure app to use bodyParser()
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// All of our routes will be prefixed with /api
app.use('/api', router);

// Test route to make sure everything is working
router.get('/', function(req, res) {
  res.json({ message: 'no.jpg' });
});

// Routes for API
router.route('/scan')

  // Create a scan (accessed at POST /api/scan)
  .post(function(req, res) {
    var scan = new Scan();
    res.json({id: scan._id,
              url: 'https://' + req.headers.host + '/api/scan/' + scan._id, });
    scan.opts = {
      range: req.body.range,
      ports: req.body.ports,
      flags: req.body.flags,
      nmap: '/app/bin/nmap',
    }
    scan.results = [{ status: 'working' }];
    scan.save(function(err) {
      if (err) { console.error(err) };
    });
    scanner.nmap('scan', scan.opts, function(err, report) {
      if (err) { console.error(err) };
      console.log('Scan complete: ' + scan._id)
      scan.results = [{ status: 'complete'}];
      scan.results.push(report);
      scan.save(function(err) {
        if (err) { console.error(err) };
      });
    });
  })

  // Get a list of scans (GET /api/scan)
  .get(function(req, res) {
    Scan.find(function(err, scan) {
      if (err) { res.send(err) };
      res.json(scan.results);
    });
  });

// Retrieve results by scanId
router.route('/scan/:scanId')

  // Get the scan with that id (accessed at GET /api/scan/:scanId)
  .get(function(req, res) {
    Scan.findById(req.params.scanId, function(err, scan) {
      if (err) { res.send(err) };
      if (!scan) {
        res.json({status: 'notfound' });
        console.log('ScanID ' + req.params.scanId + ' not found');
      } else if (scan.results === [{ status: 'working' }]) {
        res.json(scan.results)
        console.log('ScanID ' + req.params.scanId + ' reqed, but still working')
      } else { res.json(scan.results) };
    });
  });

// Start the server
app.listen(port);
