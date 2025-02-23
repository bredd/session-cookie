/*!
 * session-cookie
 * Based on cookie-session by Jonathan Ong and Douglas Christopher Wilson
 * 
 * Modified by Brandt Redd for compatibility with Passport 0.6.0 and later
 * MIT Licensed
 */

'use strict'

/**
 * Module dependencies.
 * @private
 */

var Buffer = require('safe-buffer').Buffer;
var Cookies = require('cookies');
var Crypto = require('crypto');
var onHeaders = require('on-headers');

/**
 * Module exports.
 * @public
 */

module.exports = cookieSession;

/**
 * Create a new cookie session middleware.
 *
 * @param {object} [options]
 * @param {string} [options.name=session] Name of the cookie to use
 * @param {string} [options.secret]
 * @param {number} [options.maxAge]
 * @param {object} [options.cookie] Optional: override default cookie options
 * @return {function} middleware
 * @public
 */

function cookieSession(options) {
    var opts = options || {};

    // Session defaults
    if (options.maxAge == null) options.maxAge = 60 * 60 * 1000; // One hour

    // cookie name
    var name = opts.name || 'session';

    // secrets
    if (!opts.secret) throw new Error('.secret required.');

    if (opts.cookie == null) opts.cookie = {};

    // cookie defaults
    if (opts.cookie.path == null) opts.cookie.path = '/';
    opts.cookie.overwrite = true; // Always overwrite
    if (opts.cookie.httpOnly == null) opts.cookie.httpOnly = true;
    opts.cookie.maxAge = opts.maxAge; // Should be same as session

    return function _cookieSession(req, res, next) {
        var cookies = new Cookies(req, res);
        var sess;

        // define req.session getter / setter
        Object.defineProperty(req, 'session', {
            configurable: true,
            enumerable: true,
            get: getSession,
            set: setSession
        });

        function getSession() {
            // already retrieved
            if (sess) {
                return sess;
            }

            // unset
            if (sess === false) {
                return null;
            }

            // get session if it is valid
            {
                const ckie = cookies.get(name, opts.cookie);
                if (ckie) {
                    const obj = detokenize(ckie, opts.secret);
                    if (obj) {
                        var ctx = new SessionContext();
                        ctx._new = false;
                        ctx._val = JSON.stringify(obj); // So we can tell if anything changes
                        return sess = Session.create(obj, ctx);
                    }
                }
            }

            // create session
            return (sess = Session.create());
        }

        function setSession(val) {
            if (val == null) {
                // unset session
                sess = false;
                return null;
            }

            if (typeof val === 'object') {
                // create a new session
                sess = Session.create(val);
                return sess;
            }

            throw new Error('req.session can only be set as null or an object.');
        }

        onHeaders(res, function setHeaders() {
            if (sess === undefined) {
                // not accessed
                return;
            }

            try {
                if (sess === false) {
                    // remove
                    cookies.set(name, '', opts.cookie);
                }
                else if (sess.isPopulated) {
                    cookies.set(name, tokenize(sess, opts.maxAge, opts.secret), opts.cookie);
                }
            }
            catch (e) {
                console.error('error saving session: %s', e.message);
            }
        });

        next();
    }
};

/**
 * Session model.
 *
 * @param {Context} ctx
 * @param {Object} obj
 * @private
 */
function Session(ctx, obj) {
    // This makes the _ctx property read-only and not show up in enumerations.
    Object.defineProperty(this, '_ctx', {
        value: ctx
    })

    if (obj) {
        Object.assign(this, obj);
    }
}

/**
 * Create new session.
 * @private
 */
Session.create = function create(obj) {
    var ctx = new SessionContext()
    return new Session(ctx, obj)
}

/**
 * Return if the session is changed for this request.
 *
 * @return {Boolean}
 * @public
 */

Object.defineProperty(Session.prototype, 'isChanged', {
    get: function getIsChanged() {
        return this._ctx._new || this._ctx._val !== JSON.stringify(this)
    }
})

/**
 * Return if the session is new for this request.
 *
 * @return {Boolean}
 * @public
 */
Object.defineProperty(Session.prototype, 'isNew', {
    get: function getIsNew() {
        return this._ctx._new
    }
})

/**
 * populated flag, which is just a boolean alias of .length.
 *
 * @return {Boolean}
 * @public
 */
Object.defineProperty(Session.prototype, 'isPopulated', {
    get: function getIsPopulated() {
        return Object.keys(this).length > 0
    }
})

/**
 * Regenerate is required by passport 0.6.0.
 */
Object.defineProperty(Session.prototype, 'regenerate', {
    value: function (cb) {
        // No real need to do anything except call the callback.
        // Regeneration is natural when the whole session is stored in the cookie.
        // Nevertheless, we set the cookie as being new as a precaution.
        this._ctx._new = true;
        cb();
    }
})

/**
 * Save is required by passport 0.6.0.
 */
Object.defineProperty(Session.prototype, 'save', {
    value: function (cb) {
        // Nothing to do except call the callback.
        // Session is updated on every response in order to refresh token and cookie expiration.
        cb();
    }
})

/**
 * Session context to store metadata.
 *
 * @private
 */
function SessionContext() {
    this._new = true
    this._val = undefined
}

/**
 * Get a time in seconds
 * @private
 */
function nowInSeconds() {
    return Math.floor(new Date().valueOf() / 1000);
}

/**
 * Calculate the hmac of a value with a secret
 *
 * @param {String} val
 * @param {String} secret
 * @return {String}
 * @private
 */
function hmac(val, secret) {
    return Crypto
        .createHmac('sha256', secret)
        .update(val)
        .digest('base64')
        .replace(/\=+$/, '');
};

/**
 * Serialize an object into a signed token.
 * @private
 */
function tokenize(obj, maxAge, key) {
    const exp = nowInSeconds() + (maxAge / 1000);
    var tokenBody = Buffer.from(JSON.stringify(obj)).toString('base64').replace(/\=+$/, '')
        + '.' + exp.toString();
    return tokenBody + '.' + hmac(tokenBody, key);
}

/**
 * Deserialize a token into an object
 * Returns null if the signature is invalid or the token has expired
 * @private
 */
function detokenize(str, key) {
    try {
        // Separate the hmac from the string
        let dot = str.lastIndexOf('.');
        if (dot < 0) {
            //console.log('Invalid token format (d2)');
            return null;
        }
        const tokenHmac = str.slice(dot + 1);
        let tokenBody = str.slice(0, dot);

        // Reject if the signature doesn't match
        if (hmac(tokenBody, key) !== tokenHmac) {
            //console.log("Invalid session token signature.");
            return null;
        }

        // Get expiration
        dot = tokenBody.lastIndexOf('.');
        if (dot < 0) {
            //console.log('Invalid token format (d1)');
            return null;
        }
        const exp = Number(tokenBody.slice(dot + 1));
        tokenBody = tokenBody.slice(0, dot);

        // Reject if expired
        if (exp && exp < nowInSeconds()) {
            //console.log("Expired session token.");
            return null;
        }

        return JSON.parse(Buffer.from(tokenBody, 'base64').toString('utf8'));
    }
    catch (err) {
        console.error('Invalid token: ', err.message);
        return null; // JSON parse failed (this should not happen as the signature would also fail)
    }
}
