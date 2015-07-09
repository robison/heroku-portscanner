// App/models/scan.js

var mongoose     = require('mongoose');
var uuid         = require('node-uuid');
var Schema       = mongoose.Schema;

var ScanSchema   = new Schema({
  _id: { type: String, default: uuid.v4 },
  range: Array,
  ports: String,
  date: Date,
  results: {type: mongoose.Schema.Types.Mixed},
});

module.exports = mongoose.model('Scan', ScanSchema);
