var crypto = require("crypto"),
    exec  = require('child_process').exec;

/**
 * pass.generate(password, callback) -> undefined
 * - password (String): password to be used as hash source
 * - callback (Function): callback
 * - param (object): used for algorithm and digest parameter
 *
 * Generates an Apache htpasswd password
 **/
exports.generate = function(password, callback, param){
    if (!param) param = {};
    var c;
    var algorithm = param.algorithm ? param.algorithm : 'sha1';
    var digest = param.digest ? param.digest : 'base64';

    var hash_prefix = {sha1: '{SHA}', md5: '$apr1$', crypt: ''};

    if (algorithm == 'crypt') {

        exec('openssl passwd -crypt "' + password.replace(/"/,"\\\"") + '"', function(error, stdout, stderr) {
            if (error) return callback && callback(E, null);
            return callback && callback(null, stdout.trim());
        });

    } else {
        try{
            var c = crypto.createHash(algorithm);
            c.update(password);
            c = c.digest(digest);

        }catch(E){
            return callback && callback(E, null);
        }
        callback && callback(null, hash_prefix[algorithm] + c);
    }
}

/**
 * pass.validate(password, hash, callback) -> undefined
 * - password (String): password to be validated
 * - hash (String): password hash to be checked against
 * - callback (Function): callback
 *
 * Checks if an Apache htpasswd password matches with its hash.
 **/
exports.validate = function(password, hash, callback){

    callback = callback || function(){};
    password = password || "";
    hash = hash && hash.trim() || "";

    var salt = "", parts;

    //SHA - {SHA}VBPuJHI7uixaa6LQGWx4s+5GKNE= (myPassword)
    if(hash.substr(0,5)=="{SHA}"){
        hash = hash.substr(5);
        return validate_sha(password, hash, callback);
    }

    //MD5 - $apr1$r31.....$HqJZimcKQFAMYayBlzkrA/ (myPassword)
    if(hash.substr(0,6)=="$apr1$" || hash.substr(0,3)=='$1$'){
        parts = hash.split("$");
        parts.shift();
        var type = parts.shift();
        salt = parts.shift();
        hash = parts.join("$");
        return validate_md5(password, hash, salt, callback, type);
    }

    // CRYPT - rqXexS6ZhobKA (myPassword)
    if(hash.length==13){
        salt = hash.substr(0,2);
        hash = hash.substr(2);
        return validate_crypt(password, hash, salt, callback);
    }

    // PLAIN
    return callback(null, password==hash);
}


/**
 * validate_sha(password, hash, callback) -> undefined
 * - password (String): password to be validated
 * - hash (String): password hash to be checked against
 * - callback (Function): callback
 * - param (object): used to specify algorithm
 *
 * Validates a SHA1 password
 **/
function validate_sha(password, hash, callback, param){
    if (!param) param = {};
    var c;
    var algorithm = param.algorithm ? param.algorithm : 'sha1';
    var digest = param.digest ? param.digest : 'base64';

    try{
        c = crypto.createHash(algorithm);
        c.update(password);
        c = c.digest(digest);
    }catch(E){
        return callback(E, null);
    }
    callback(null, c==hash);
}

/**
 * validate_sha(password, hash, callback) -> undefined
 * - password (String): password to be validated
 * - hash (String): password hash to be checked against
 * - callback (Function): callback
 * - which password algorithm, defaults to "MD5-based password algorithm, Apache variant"
 *
 * Validates an APR1/MD5 password
 **/
function validate_md5(password, hash, salt, callback, type){
    type = type ? type : 'apr1';

    exec(
            'openssl passwd -'+type+' -salt '+salt+' "'+password.replace(/"/,"\\\"")+'"',
            function (error, stdout, stderr) {
                if(error){
                    return callback(error, null);
                }
                callback(null, stdout && stdout.trim()=='$'+type+'$'+salt+'$'+hash);
            }
    );
}

/**
 * validate_sha(password, hash, callback) -> undefined
 * - password (String): password to be validated
 * - hash (String): password hash to be checked against
 * - callback (Function): callback
 *
 * Validates a Linux crypt(3) password
 **/
function validate_crypt(password, hash, salt, callback){
    exec(
            'openssl passwd -crypt -salt '+salt+' "'+password.replace(/"/,"\\\"")+'"',
            function (error, stdout, stderr) {
                if(error){
                    return callback(error, null);
                }
                callback(null, stdout && stdout.trim()==salt+hash);
            }
    );
}
