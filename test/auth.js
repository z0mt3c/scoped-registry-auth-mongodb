var Lab = require('lab');
var lab = exports.lab = Lab.script();

var describe = lab.describe;
var it = lab.it;
var before = lab.before;
var after = lab.after;
var expect = Lab.expect;

var config = require('./config.json');
var Strategy = require('../lib');
var mongodb = require('mongodb');
var Hoek = require('hoek');

describe('authentication', function () {
    var db, auth;

    var dropDb = function (done) {
        db.dropDatabase(function () {
            auth = new Strategy({mongodb: db});
            done();
        });
    };

    before(function (done) {
        mongodb.MongoClient.connect(config.mongodb, function (err, database) {
            Hoek.assert(!err, 'Database connection failed');
            db = database;
            dropDb(done);
        });
    });

    after(function (done) {
        db.close(function () {
            done();
        });
    });

    describe('validateCredentials', function () {
        before(dropDb);

        it('not found', function (done) {
            auth.validateCredentials({name: 'john', password: 'doe'}, function (error, results) {
                expect(error).not.to.exist;
                expect(results).to.exist;
                expect(results).to.be.false;
                done();
            });
        });

        it('register', function (done) {
            auth.registerUser({name: 'john', password: 'doe', email: 'john@doe.tld'}, function (error, results) {
                expect(error).not.to.exist;
                expect(results).to.exist;
                done();
            });
        });

        it('valid', function (done) {
            auth.validateCredentials({name: 'john', password: 'doe'}, function (error, results) {
                expect(error).not.to.exist;
                expect(results).to.exist;
                expect(results).to.be.true;
                done();
            });
        });

        it('invalid', function (done) {
            auth.validateCredentials({name: 'john', password: 'doe1'}, function (error, results) {
                expect(error).not.to.exist;
                expect(results).to.exist;
                expect(results).to.be.false;
                done();
            });
        });
    });

    describe('validateToken', function () {
        before(dropDb);

        it('not found', function (done) {
            auth.validateToken({name: 'john'}, function (error, results) {
                expect(error).not.to.exist;
                expect(results).to.exist;
                expect(results).to.be.false;
                done();
            });
        });

        it('register', function (done) {
            auth.registerUser({name: 'john', password: 'doe', email: 'john@doe.tld'}, function (error, results) {
                expect(error).not.to.exist;
                expect(results).to.exist;
                done();
            });
        });

        it('user found', function (done) {
            auth.validateToken({name: 'john'}, function (error, results) {
                expect(error).not.to.exist;
                expect(results).to.exist;
                expect(results).to.be.true;
                done();
            });
        });
    });

    describe('registerUser', function () {
        before(dropDb);

        it('works', function (done) {
            auth.registerUser({name: 'john', password: 'doe', email: 'john@doe.tld'}, function (error, results) {
                expect(error).not.to.exist;
                expect(results).to.exist;
                done();
            });
        });

        it('duplicate', function (done) {
            auth.registerUser({name: 'john', password: 'doe', email: 'john@doe.tld'}, function (error, results) {
                expect(error).to.exist;
                expect(results).not.to.exist;
                done();
            });
        });
    });
});
