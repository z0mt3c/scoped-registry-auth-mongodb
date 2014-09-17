var Hoek = require('hoek');
var bcrypt = require('bcrypt');
var SALT_WORK_FACTOR = 10;
var _ = require('lodash');
var crypto = require('crypto');

var internals = {
	createChecksum: function (string) {
		var shasum = crypto.createHash('sha1');
		shasum.update(string);
		return shasum.digest('hex');
	},
	createTokenData: function (user) {
		var tokenData = {
			name: user.name,
			hash: internals.createChecksum(user.password)
		};

		return tokenData;
	}
};

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

			if (isMatch) {
				var tokenData = internals.createTokenData(userDocument);
				return next(null, isMatch, tokenData);
			} else {
				return next(null, false);
			}
		});
	});
};

AuthenticationStrategy.prototype.validateTokenData = function (tokenData, next) {
	this.db.collection(this.options.collection).findOne({_id: tokenData.name}, function (error, userDocument) {
		if (error || !userDocument) {
			return next(error, false);
		} else {
			var hash = internals.createChecksum(userDocument.password);
			return next(null, hash && tokenData.hash == hash);
		}
	});
};

AuthenticationStrategy.prototype.createUser = function (user, next) {
	var self = this;

	bcrypt.hash(user.password, SALT_WORK_FACTOR, function (error, hash) {
		if (error) return next(error);
		var userData = {_id: user.name, name: user.name, password: hash};

		self.db.collection(self.options.collection).insert(userData, function (error, doc) {
			var tokenData = !error && doc && doc.length === 1 ? internals.createTokenData(doc[0]) : null;
			next(error, tokenData);
		});
	});
};
