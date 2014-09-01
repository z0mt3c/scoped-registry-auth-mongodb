var Hoek = require('hoek');
var bcrypt = require('bcrypt');
var SALT_WORK_FACTOR = 10;
var _ = require('lodash');

var AuthenticationStrategy = module.exports = function (options) {
    Hoek.assert(options, 'Options missing');
    Hoek.assert(options.mongodb, 'Mongodb connection instance missing');
    this.options = options;
    this.db = this.options.mongodb;
};

AuthenticationStrategy.prototype.validateCredentials = function (user, next) {
    this.db.collection('user').findOne({_id: user.name}, function (error, userDocument) {
        if (error) return next(err);
        if (!userDocument) return next(null, null);

        bcrypt.compare(user.password, userDocument.password, function (error, isMatch) {
            if (error) return next(err);
            return next(null, isMatch);
        });
    });
};

AuthenticationStrategy.prototype.validateToken = function (user, next) {
    this.db.collection('user').findOne({_id: user.name}, function (error, userDocument) {
        if (error) return next(error);
        return next(null, userDocument !== null);
    });
};

AuthenticationStrategy.prototype.createTokenData = function (user, next) {
    var tokenData = _.pick(user, ['name', 'email'])
    return next(null, tokenData);
};

AuthenticationStrategy.prototype.createUser = function (user, next) {
    var self = this;

    bcrypt.genSalt(SALT_WORK_FACTOR, function (error, salt) {
        if (error) return next(error);
        bcrypt.hash(user.password, salt, function (error, hash) {
            if (error) return next(error);
            user.password = hash;
            user._id = user.name;
            self.db.collection('user').insert(user, function (error, doc) {
                next(error, doc);
            });
        });
    });
};