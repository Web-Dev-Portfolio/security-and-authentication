//jshint esversion:6
require("dotenv").config() //level 3 encrypt
const express = require("express")
const bodyParser = require("body-parser")
const ejs = require("ejs")
const app = express()
const mongoose = require("mongoose")
// const encrypt = require("mongoose-encryption") //level 3 encrypt
// const md5 = require("md5") // level 4 hash
// const bcrypt = require("bcrypt") // level 5 salting and hashing
const session = require("express-session") //cookies & session
const passport = require("passport") //cookies & session
const passportLocalMongoose = require("passport-local-mongoose") //cookies & session
const GoogleStrategy = require("passport-google-oauth20").Strategy; // Google OAuth 2.0
const findOrCreate = require("mongoose-findorcreate") // another npm helper


const saltRounds = 10

app.use(express.static("public"))
app.use(bodyParser.urlencoded({
    extended: true
}))
app.set("view engine", "ejs")
app.use(session({
    secret: "It's a very big secret and we cant tell anybody",
    resave: false,
    saveUninitialized: true,
}))
app.use(passport.initialize())
app.use(passport.session())

mongoose.connect("mongodb://localhost:27017/secretDB", {
    useNewUrlParser: true
})

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId : String
})

userSchema.plugin(passportLocalMongoose) //cookies & session
userSchema.plugin(findOrCreate) // google OAuth npm

const User = new mongoose.model("User", userSchema)

passport.use(User.createStrategy()) //cookies & session

//serialize and deserialize using Local
// passport.serializeUser(User.serializeUser()) //cookies & session
// passport.deserializeUser(User.deserializeUser()) //cookies & session

//serialize and deserialize using Oauth
passport.serializeUser(function (user, done) {
    // process.nextTick(function () {
    //     cb(null, {
    //         id: user.id,
    //         username: user.username,
    //         name: user.name
    //     });
    // });
    done(null , user.id)
});

passport.deserializeUser(function (id, done) {
    // process.nextTick(function () {
    //     return cb(null, user);
    // });
    User.findById(id, function(err, user){
        done(err, user)
    })
});


// Ouath strategy should put here and any authentication
passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/secrets",
        userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
    },
    function (accessToken, refreshToken, profile, cb) {
        console.log(profile);
        
        User.findOrCreate({
            googleId: profile.id
        }, function (err, user) {
            return cb(err, user);
        });
    }
));


// PREVIOUS
// level 2  encrypt
// const secret = "ThisIsMyLittleSecret"
// userSchema.plugin(encrypt, { secret : secret, encryptedFields : ["password"]})

// level 3 - .env 
// userSchema.plugin(encrypt, { secret : process.env.SECRET, encryptedFields : ["password"]})
// console.log(process.env.SECRET);


// Level 4 - Hashing
// in POST/Register
// const newUser = new User({
//     email : req.body.username,
//     password : md5(req.body.password) // level 4 hash function  for level 3 no need any function
// })

// newUser.save( function(err) {
//     if (err) {
//         console.log(err)
//     } 
//     else {
//         res.render("secrets")
//     }
// })

// in GET/Login
// const username = req.body.username
// const password = md5(req.body.password) // level 4 combining hash with hash

// User.findOne ( { email : username }, (err, foundUser) => {
//     if (err) {
//         console.log(err);
//     } else {
//         if (foundUser) {
//             if ( foundUser.password === password) {
//                 res.render("secrets") // level 1
//             }
//         }
//         else {
//             res.render("/login")
//             console.log("Wrong password");
//         }
//     }
// })



// Level 5 Salting + Hashing
// POST Login
// const username = req.body.username
//     const password = req.body.password // level 4 combining hash with hash

//     User.findOne ( { email : username }, (err, foundUser) => {
//         if (err) {
//             console.log(err);
//         } else {
//             if (foundUser) {
//                 // this compare plain text from user input with hashed version in database
//                 bcrypt.compare(password, foundUser.password, function(err, result) {
//                     if( result == true) {
//                         res.render("secrets") // level 5
//                     }   
//                 });
//             }
//             else {
//                 res.render("/login")
//                 console.log("Wrong password");
//             }
//         }
//     })


// POST Register
// bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
//     // Store hash in your password DB.
//     const newUser = new User({
//         email : req.body.username,
//         password : hash
//     })

//     newUser.save( function(err) {
//         if (err) {
//             console.log(err)
//         } 
//         else {
//             res.render("secrets")
//         }
//     })
// });



app.get("/", (req, res) => {
    res.render("home")
})

app.route("/login")
    .get((req, res) => {
        res.render("login")
    })
    .post((req, res) => {

        const user = new User({
            username: req.body.username,
            password: req.body.password
        })

        req.login(user, (err) => {
            if (err) {
                console.log(err);
            } else {
                passport.authenticate("local")(req, res, () => {
                    res.redirect("/secrets")
                })
            }
        })
    })

app.route("/register")
    .get((req, res) => {
        res.render("register")
    })
    .post((req, res) => {

        //cookies & session
        User.register({
            username: req.body.username
        }, req.body.password, (err, user) => {
            if (err) {
                console.log(err)
                res.redirect("/register")
            } else {
                passport.authenticate("local")(req, res, () => {
                    res.redirect("/secrets")
                })
            }
        })

    })

//cookies & session
app.get("/secrets", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("secrets")
    } else {
        res.redirect("/login")
    }
})

//cookies & session
app.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) console.log(err);
    })
    res.redirect("/")
})

// google OAuth 2.0
app.get("/auth/google",
    passport.authenticate("google", {
        scope: ["profile"]
    }));

app.get("/auth/google/secrets",
    passport.authenticate("google", {
        failureRedirect: "/"
    }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect("/secrets");
    });

app.listen(3000, () => {
    console.log("server is on!");
})