/**
 * Copyright (c) 2013 Sam Decrock https://github.com/SamDecrock/
 * All rights reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

'use strict';

var ntlm = require('./ntlm');
var axios = require('axios');
var _ = require('underscore');

exports.method = function(method, options, finalCallback) {
  if(!options.workstation) options.workstation = '';
  if(!options.domain) options.domain = '';

  // extract non-ntlm-options:
  var httpreqOptions = _.omit(options, 'url', 'username', 'password', 'workstation', 'domain');

  // build type1 request:

  function sendType1Message(callback) {
    var type1msg = ntlm.createType1Message(options);

    var type1options = {
      headers:{
        'Connection' : 'keep-alive',
        'Authorization': type1msg
      },
      timeout: options.timeout || 0,
      maxRedirects: 0
    };
    
    type1options.url = options.url;
    type1options.method = method;
    // pass along other options:
    if(options.ntlm && options.ntlm.strict) {
      // strict no need to pass other parameters
      type1options = _.extend({}, _.omit(httpreqOptions, 'headers', 'body'), type1options);
    }
    else {
      // not strict pass other parameters so as to continue if everything passes
      type1options.headers = _.extend(type1options.headers, httpreqOptions.headers);
      type1options = _.extend(type1options, _.omit(httpreqOptions, 'body', 'data', 'headers'));
      type1options.data = httpreqOptions.data || httpreqOptions.body;
    }

    // send type1 message to server:
    axios.request(type1options)
    .then(function(res) {
      callback(null, res);
    })
    .catch(function(err) {
      if(err.response) {
        if(err.response.status === 401) {
          callback(null, err.response);
        }
        else {
          callback(err.response);
        }
      }
      else {
        callback(err);
      }
    });
  }

  function sendType3Message(res, callback) {
    // catch redirect here:
    if(res.headers.location) { // make sure your server has the following header Access-Control-Expose-Headers: location, www-authenticate  
      options.url = res.headers.location;
      return exports[method](options, finalCallback);
    }

    if(!res.headers['www-authenticate']) { // make sure your server has the following header Access-Control-Expose-Headers: location, www-authenticate  
      if(options.ntlm && options.ntlm.strict) {
        return callback(new Error('www-authenticate not found on response of second request'));
      }
      else {
        if(res.status === 401) {
          console.warn('If this 401 response is unexpected, make sure your server sets "Access-Control-Expose-Headers" to "location, www-authenticate"');
        }
        return callback(null, res);
      }
    }

    // parse type2 message from server:
    var type2msg = ntlm.parseType2Message(res.headers['www-authenticate'], callback); //callback only happens on errors
    if(!type2msg) return; // if callback returned an error, the parse-function returns with null

    // create type3 message:
    var type3msg = ntlm.createType3Message(type2msg, options);

    // build type3 request:
    var type3options = {
      headers: {
        'Connection': 'Close',
        'Authorization': type3msg
      },
      maxRedirects: 0
    };

    // pass along other options:
    type3options.headers = _.extend(type3options.headers, httpreqOptions.headers);
    type3options = _.extend(type3options, _.omit(httpreqOptions, 'body', 'data', 'headers'));
    type3options.url = options.url;
    type3options.method = method;
    type3options.data = httpreqOptions.data || httpreqOptions.body;

    // send type3 message to server:
    axios.request(type3options)
    .then(function(res) {
      callback(null, res);
    })
    .catch(function(err) {
      if(err.response) {
        callback(err.response);
      }
      else {
        callback(err);
      }
    });
  }


  sendType1Message(function(err, res) {
    if(err) return finalCallback(err);
    setTimeout(function() {
      sendType3Message(res, finalCallback);
    });
  });

};

['get', 'put', 'patch', 'post', 'delete', 'options'].forEach(function(method) {
  exports[method] = exports.method.bind(exports, method);
});

exports.ntlm = ntlm; //if you want to use the NTML functions yourself

