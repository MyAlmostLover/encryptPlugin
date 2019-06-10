var exec = require('cordova/exec');

exports.coolMethod = function (arg0, success, error) {
    exec(success, error, 'encryption', 'coolMethod', [arg0]);
};

exports.Decrypt = function (arg0, arg1, arg2, success, error) {
    exec(success, error, 'encryption', 'Decrypt', [arg0, arg1, arg2]);
};

exports.Encrypt = function (arg0, arg1, arg2, success, error) {
    exec(success, error, 'encryption', 'Encrypt', [arg0, arg1, arg2]);
};