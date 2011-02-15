pass
====

Simple module for Node.JS to generate/validate passwords from Apache htpasswd files.

The module supports Apache Basic Auth password formats - `crypt(3)`, `apr1/md5`, `sha1`, `plain`.

All generated passwords are in `sha1` format.

Requirements
------------

  * OpenSSL

Installation
------------

    npm install pass

Usage
-----

Simple use-case - generate a hash from a password and validate it.

    var pass = require("pass");

    var password = "myPassword";
    
    // generate a password hash
    pass.generate(password, function(error, hash){
        if(error){
            console.log("Error occured: "+error.message);
            return;
        }
    
        
        // validate a password
        pass.validate(password, hash, function(error, success){
            if(error){
                console.log("Error occured: "+error.message);
                return;
            }
    
            console.log(success?"Passwords matched!":"No match!");
        });
            
    });

See [test.js](https://github.com/andris9/pass/blob/master/test.js) for a better example

License
-------

MIT