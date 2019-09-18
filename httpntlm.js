/**
 * Copyright (c) 2013 Sam Decrock https://github.com/SamDecrock/
 * All rights reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

'use strict';

var ntlm = require('./ntlm');

function omit(obj) {
  var toOmit = {};
  for(var i = 1; i < arguments.length; i++) {
    toOmit[arguments[i]] = true;
  }
  var ret = {};
  for(var i in obj) {
    if(!toOmit[i]) {
      ret[i] = obj[i]
    }
  }
  return ret;
}

function getRequest(options) {
  if(options.request) {
    return options.request;
  }
  var ret;
  try {
    ret = function(options) {
      return fetch(options.url, options);
    };
  }
  catch(err) { }
  if(ret) {
    return ret;
  }
  throw new Error('No request function provided, and couldn\'t find fetch in scope!');
}

function internalRequest(options) {

  var _Promise = (options.Promise || Promise);

  if(!options.workstation) options.workstation = '';
  if(!options.domain) options.domain = '';

  // extract non-ntlm-options:
  var httpReqExtraOptions = omit(options, 'method', 'url', 'headers', 'body', 'request', 'username', 'password', 'lm_password', 'nt_password', 'workstation', 'domain', 'ntlm');
  var url = options.url;
  var method = options.method;
  var headers = options.headers;
  var body = options.body;
  var request = getRequest(options);
  var isStrict = options.ntlm && options.ntlm.strict;

  // build type1 request:

  function sendType1Message() {
    var type1msg = ntlm.createType1Message(options);

    var type1options = {
      url: url,
      method: method,
      headers: {
        'Connection' : 'keep-alive',
        'Authorization': type1msg
      }
    };
    
    // pass along other options:
    if(isStrict) {
      // strict no need to pass other parameters
      type1options = Object.assign(type1options, httpReqExtraOptions);
    }
    else {
      // not strict pass other parameters so as to continue if everything passes
      type1options.headers = Object.assign({}, headers, type1options.headers);
      type1options.body = body;
      type1options = Object.assign(type1options, httpReqExtraOptions);
    }

    // send type1 message to server:
    return request(type1options);
  }

  function sendType3Message(res) {
    // catch redirect here:
    var location = res.headers.get ? res.headers.get('location') : res.headers['location'];
    if(location) { // make sure your server has the following header Access-Control-Expose-Headers: location, www-authenticate
      return internalRequest(Object.assign({}, options, { url: location }));
    }

    var wwwAuthenticate = res.headers.get ? res.headers.get('www-authenticate') : res.headers['www-authenticate'];
    if(!wwwAuthenticate) { // make sure your server has the following header Access-Control-Expose-Headers: location, www-authenticate  
      if(isStrict) {
        return _Promise.reject(new Error('www-authenticate not found on response of second request'));
      }
      else {
        if(res.status === 401) {
          console.warn('If this 401 response is unexpected, make sure your server sets "Access-Control-Expose-Headers" to "location, www-authenticate"');
        }
        return _Promise.resolve(res);
      }
    }

    // parse type2 message from server:
    var type2msg;
    try {
      type2msg = ntlm.parseType2Message(wwwAuthenticate);
    }
    catch(err) {
      return _Promise.reject(err);
    }

    // create type3 message:
    var type3msg = ntlm.createType3Message(type2msg, options);

    // build type3 request:
    var type3options = {
      url: url,
      method: method,
      headers: {
        'Connection': 'Close',
        'Authorization': type3msg
      }
    };

    // pass along other options:
    type3options.headers = Object.assign({}, headers, type3options.headers);
    type3options = Object.assign(type3options, httpReqExtraOptions);

    // send type3 message to server:
    return request(type3options);
  }

  return sendType1Message()
  .then(function(res) {
    if(res.status === 401) {
      return sendType3Message(res);
    }
    else {
      return res;
    }
  });

};

exports.request = function(options, finalCallback) {
  var ret = internalRequest(options);
  if(finalCallback) {
    ret.then(function(res) {
      try {
        finalCallback(null, res);
      }
      catch(err) {
        return err;
      }
    })
    .catch(function(err) {
      finalCallback(err);
    })
    .then(function(error) {
      if(error) {
        throw error;
      }
    });
  }
  return ret;
};

exports.method = function(method, options, finalCallback) {
  options = Object.assign({ method }, options);
  return exports.request(options, finalCallback);
};

['get', 'put', 'patch', 'post', 'delete', 'options'].forEach(function(method) {
  exports[method] = function(options, finalCallback) {
    options = Object.assign({ method }, options);
    return exports.request(options, finalCallback);
  }
});

exports.ntlm = ntlm; //if you want to use the NTML functions yourself

