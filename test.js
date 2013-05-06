var pass = require("./pass");

// generate a password
pass.generate("myPassword", function(error, hash){
    if(error){
        return console.log("Error: "+error.message);
    }
    console.log("Password generation: "+ (hash == "{SHA}VBPuJHI7uixaa6LQGWx4s+5GKNE="?"OK":"Failed"));
})

// check predefined passwords
function response(type, expected, error, success){
    console.log(type+": "+(success==expected?"OK":"Failed"));
}

pass.validate("myPassword", "{SHA}VBPuJHI7uixaa6LQGWx4s+5GKNE=", response.bind(this, "SHA1  True ", true));
pass.validate("myPass", "{SHA}VBPuJHI7uixaa6LQGWx4s+5GKNE=", response.bind(this, "SHA1  False", false));

pass.validate("myPassword", "$apr1$r31.....$HqJZimcKQFAMYayBlzkrA/", response.bind(this, "MD5   True ", true));
pass.validate("myPass", "$apr1$r31.....$HqJZimcKQFAMYayBlzkrA/", response.bind(this, "MD5   False", false));

pass.validate("myPassword", "$1$saltsalt$2vnaRpHa6Jxjz5n83ok8Z0", response.bind(this, "MD5_1 True ", true));
pass.validate("myPass", "$1$saltsalt$2vnaRpHa6Jxjz5n83ok8Z0", response.bind(this, "MD5_1 False ", false));

pass.validate("myPassword", "rqXexS6ZhobKA", response.bind(this, "CRYPT True ", true));
pass.validate("myPass", "rqXexS6ZhobKA", response.bind(this, "CRYPT False", false));
