require('dotenv').config();
const express=require('express');
const ejs=require('ejs');
const bodyParser=require('body-parser');
const mongoose=require('mongoose');
const encrypt=require('mongoose-encryption');
const session = require('express-session')
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate')
// salt rounds - more salt rounds means more computation time
// const saltRounds = 10; 

const app=express();
app.use(bodyParser.urlencoded({extended:true}));
app.use(express.static("public"));
app.set("view engine","ejs");

app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://127.0.0.1:27017/userDB");

const userSchema = new mongoose.Schema({
    email:String,
    password:String,
    googleId:String,
    facebookId:String,
    secret:[String]
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//const secret="Thisisourlittlesecret.";
//console.log(process.env.SECRET);
//userSchema.plugin(encrypt,{secret:process.env.SECRET, encryptedFields: ['password']});

const userModel = mongoose.model("user",userSchema);

passport.use(userModel.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user);
  });
  
  passport.deserializeUser(function(user, done) {
    done(null, user);
  });

// 86985e105f79b95d6bc918fb45ec7727
//console.log(md5("test4"));

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    // userProfileURL: "https://www.googleapis.com/auth/userinfo.profile"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    userModel.findOrCreate({ username: profile.id, googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_CLIENT_ID,
    clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    userModel.findOrCreate({ username: profile.id,facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.listen(3000,function(){
    console.log("Server is running on port 3000");
});

app.get("/",function(req,res){
    res.render("home");
});

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect("/secrets");
  });
  
  app.get('/auth/facebook',
  passport.authenticate('facebook'));

  app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/login",function(req,res){
    res.render("login");
});

app.get("/register",function(req,res){
    res.render("register");
});

app.get("/secrets",function(req,res){
    // userModel.find({secret:{$ne:null}}).then(function(data){
    //     console.log(data);
    //     res.send("in development...");
    // });
    userModel.find({secret:{$ne:null}}).then(function(foundUsers){
        if(foundUsers)
            res.render("secrets",{usersWithSecrets:foundUsers});
    });
});

app.post("/register",function(req,res){
    userModel.register({username:req.body.username},req.body.password,function(err,user){
        if(err)
        {
            console.log(err);
            res.redirect("/register");
        }
        else
        {
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/login",function(req,res){
    const newUser = new userModel({
        username:req.body.username,
        password:req.body.password
    });

    req.login(newUser,function(err){
        if(err){
            console.log(err);
        }
        else
        {
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });
        }
    });
});

app.get("/logout",function(req,res){
    // deauthenticate the users

    // req.logout() requires a callback
    // if no callback, error will be there
    req.logout(function(err) {
        if (err) { 
            console.log(err);
        }
        res.redirect("/");
    });
});

app.get("/submit",function(req,res){
    if(req.isAuthenticated())
        res.render("submit");
    else
        res.redirect("/login");
});

app.post("/submit",function(req,res){
    const submittedSecret=req.body.secret;
    //console.log("User currently = ",req.user);
    const user_id=req.user._id;
    userModel.findById(user_id).then(function(user_found){
        if(user_found)
        {
            user_found.secret.push(submittedSecret);;
            user_found.save().then(function(){
                console.log("Saved successfully!");
                res.redirect("/secrets");
            });
        }
        else
            console.log("User not found!");
    });
});