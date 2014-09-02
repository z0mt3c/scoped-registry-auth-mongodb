var Hoek = require('hoek');
var bcrypt = require('bcrypt');
var SALT_WORK_FACTOR = 10;
var _ = require('lodash');

var AuthenticationStrategy = module.exports = function (options) {
    Hoek.assert(options, 'Options missing');
    Hoek.assert(options.mongodb, 'Mongodb connection instance missing');
    this.options = options;
    this.db = this.options.mongodb;
    this.options.collection = this.options.collection || 'user';
};

AuthenticationStrategy.prototype.validateCredentials = function (user, next) {
    var self = this;
    this.db.collection(self.options.collection).findOne({_id: user.name}, function (error, userDocument) {
        if (error) return next(err);
        if (!userDocument) return next(null, null);

        bcrypt.compare(user.password, userDocument.password, function (error, isMatch) {
            if (error) return next(err);

            // Update email if changed
            if (userDocument.email !== user.email) {
                self.db.collection(self.options.collection).update({_id: user.name}, {$set: {email: user.email}}, function() {
                    return next(null, isMatch);
                });
            } else {
                return next(null, isMatch);
            }
        });
    });
};

AuthenticationStrategy.prototype.validateToken = function (user, next) {
    this.db.collection(this.options.collection).findOne({_id: user.name}, function (error, userDocument) {
        if (error) return next(error);
        return next(null, userDocument !== null);
    });
};

AuthenticationStrategy.prototype.createTokenData = function (user, next) {
    var tokenData = _.pick(user, ['name', 'email']);
    return next(null, tokenData);
};

AuthenticationStrategy.prototype.createUser = function (user, next) {
    var self = this;
    var userData = _.pick(user, ['name', 'email']);

    bcrypt.hash(user.password, SALT_WORK_FACTOR, function (error, hash) {
        if (error) return next(error);
        userData.password = hash;
        userData._id = user.name;
        self.db.collection(self.options.collection).insert(userData, function (error, doc) {
            next(error, doc);
        });
    });
};