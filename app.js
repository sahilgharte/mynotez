require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const crypto = require('crypto');
const mongoose = require('mongoose');
const multer = require('multer');
const GridFsStorage = require('multer-gridfs-storage');
const Grid = require('gridfs-stream');
const methodOverride = require('method-override');
const session = require('express-session');
const passport = require('passport');
const flash = require("express-flash");
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const async = require('async');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt-nodejs');

const app = express();
app.use(flash());

app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static('public'));
app.set("view engine", "ejs" );


app.use(session({
  secret: process.env.SECRET,
  resave:false,
  saveUninitialized:false

}));


app.use(passport.initialize());
app.use(passport.session());






// Mongo URI
const mongoURI = process.env.DATA_BASE_URI;

//connection establish
mongoose.connect(mongoURI ,{useNewUrlParser: true , useUnifiedTopology: true});
console.log("DB Connected");


mongoose.set('useCreateIndex', true);

const userSchema = new mongoose.Schema({
  // email: {type:String,unique:true,required:true},
  email:{type: String, require: true, index: true, unique: true, sparse: true },
  password:String,
  googleId:{type: String, index: true, unique: true, sparse: true },
  resetPasswordToken: String,
  resetPasswordExpires: Date
})

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
// userSchema.plugin(require('mongoose-beautiful-unique-validation'));


const User = new mongoose.model("User",userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});



passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: process.env.CALLBACKURL,
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    passReqToCallback   : true,
  },
  function(request, accessToken, refreshToken, profile, done) {
    User.findOne({ googleId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));





// Mongo URI
// const mongoURI = 'mongodb+srv://aman:aman@collegedb.jrkkn.mongodb.net/testUpload?retryWrites=true&w=majority';

// Create mongo connection
const conn = mongoose.createConnection(mongoURI, {useNewUrlParser: true, useUnifiedTopology: true});

// Init gfs
let gfs;

//this function is used for searching operation
function escapeRegex(text) {
    return text.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, "\\$&");
};

conn.once('open', () => {
  // Init stream
  gfs = Grid(conn.db, mongoose.mongo);
  gfs.collection('uploads');
});


// Create storage engine
const storage = new GridFsStorage({
  url: mongoURI,
  options:{useUnifiedTopology: true},
  file: (req, file) => {
    return new Promise((resolve, reject) => {
      crypto.randomBytes(16, (err, buf) => {
        if (err) {
          return reject(err);
        }
        // const filename = buf.toString('hex') + path.extname(file.originalname);

      });
      const filename = file.originalname;
      const fileInfo = {
        filename: filename,
        bucketName: 'uploads'
      };
      resolve(fileInfo);
    });
  }
});


//@route GET /
//@dec home or landing page
app.get("/",(req,res)=>{
  res.render("home");
});

//@route GET /:collegename
//@dec landing page of college
app.get('/allfiles', (req,res)=>{
  if(req.query.search){
    const regex = new RegExp(escapeRegex(req.query.search), 'gi');
    gfs.files.find({filename: regex }).toArray((err, files) => {
      // Check if files
      if (!files || files.length === 0) {
        res.render('college', { files: false });
      } else {
        files.map(file => {
          if (
            file.contentType === 'image/jpeg' ||
            file.contentType === 'image/png'
          ) {
            file.isImage = true;
          } else {
            file.isImage = false;
          }
        });
        res.render('college', { files: files });
      }
    });

  }else{
    gfs.files.find().toArray((err, files) => {
      // Check if files
      if (!files || files.length === 0) {
        res.render('college', { files: false });
      } else {
        files.map(file => {
          if (
            file.contentType === 'image/jpeg' ||
            file.contentType === 'image/png'
          ) {
            file.isImage = true;
          } else {
            file.isImage = false;
          }
        });
        res.render('college', { files: files });
      }
    });
  }
});

//@route GET /:collegename
//@dec landing page of college
app.get('/upload', (req,res)=>{
  if(req.isAuthenticated()){
    if(req.query.search){
    const regex = new RegExp(escapeRegex(req.query.search), 'gi');
    gfs.files.find({filename: regex }).toArray((err, files) => {
      // Check if files
      if (!files || files.length === 0) {
        res.render('upload', { files: false });
      } else {
        files.map(file => {
          if (
            file.contentType === 'image/jpeg' ||
            file.contentType === 'image/png'
          ) {
            file.isImage = true;
          } else {
            file.isImage = false;
          }
        });
        res.render('upload', { files: files });
      }
    });

  }else{
    gfs.files.find().toArray((err, files) => {
      // Check if files
      if (!files || files.length === 0) {
        res.render('upload', { files: false });
      } else {
        files.map(file => {
          if (
            file.contentType === 'image/jpeg' ||
            file.contentType === 'image/png'
          ) {
            file.isImage = true;
          } else {
            file.isImage = false;
          }
        });
        res.render('upload', { files: files });
      }
    });
  }
  }else{
    res.redirect("/login");
  }

});


// @route DELETE /files/:id
// @desc  Delete file
app.post('/upload/:id', (req, res) => {
  gfs.remove({ _id: req.params.id, root: 'uploads' }, (err, gridStore) => {
    if (err) {
      // return res.status(404).json({ err: err });
      res.render('error');
    }

    res.redirect('/upload');
  });
});

//@route /download/:file name
//@desc for downloading the files
app.post('/download/:filename', (req, res) => {
  gfs.files.findOne({ filename: req.params.filename }, (err, file) => {
    // Check if file
    if (!file || file.length === 0) {
      // return res.status(404).json({
      //   err: 'No file exists yaha problem hai bro'
      // });
      res.render('error');
    }
    // File exists
    res.set('Content-Type', file.contentType);
    res.set('Content-Disposition', 'attachment; filename="' + file.filename + '"');
    // streaming from gridfs
    var readstream = gfs.createReadStream({
      filename: req.params.filename
    });
    const writestream = gfs.createWriteStream({
         filename: req.params.filename
      })
    //error handling, e.g. file does not exist
    readstream.on('error', function (err) {
      console.log('An error occurred!', err);
      throw err;
    });
    readstream.pipe(res);
  });
});


const upload = multer({ storage });

//@route GET /Upload
//@dec upload page
app.get("/upload", (req,res)=>{
  if(req.isAuthenticated()){
    res.render('upload');
  }else{
    res.redirect("/login");
  }
});


// @route POST /upload
// @desc  Uploads file to DB
app.post('/upload', upload.single('file'), (req, res) => {
   // res.json({ file: req.file });
   res.redirect('/upload');
});



// ******************************************************Auth************************************************

app.get("/auth/google",
  passport.authenticate('google',{scope:["email", "profile"]})
)

app.get('/auth/google/upload',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/upload');
  });


app.get("/login",function(req,res){
  res.render("login");
});

app.get("/htu",function(req,res){
  res.render("htu");
})

// app.get("/"+process.env.REGISTER,function(req,res){
//   res.render("register");
// });

app.get("/logout",function(req,res){
  req.logout();
  res.redirect("/");
});


app.post("/login",function(req,res){
      const user = new User({
    username:req.body.username,
    password:req.body.password
  });

  req.login(user,function(err){
    if(err){
      // console.log(err);
      res.render('error');
    }else{
      passport.authenticate("local")(req,res,function(){
        res.redirect("/upload");
      })
    }
  });
});

// app.post("/"+process.env.REGISTER,function(req,res){
//     User.register({username:req.body.username},req.body.password,function(err,user){
//     if(err){
//       console.log(err);
//       res.redirect("/"+process.env.REGISTER);
//     }else{
//       passport.authenticate("local")(req,res,function(){
//         res.redirect("/upload");
//       })
//     }
//   })
// });


// forgot password
app.get('/forgot', function(req, res) {
  res.render('forgot');
});

app.get('/error',function(req,res){
  res.render('error');
})


app.get("/reset",function(req,res){
  res.render("reset");
});


// forgot password
app.get('/forgot', function(req, res) {
  res.render('forgot');
});

app.post('/forgot', function(req, res, next) {
  async.waterfall([
    function(done) {
      crypto.randomBytes(20, function(err, buf) {
        var token = buf.toString('hex');
        done(err, token);
      });
    },
    function(token, done) {
      User.findOne({ username:req.body.email }, function(err, user) {
        if (!user) {
          req.flash('error', 'No account with that email address exists.');
          return res.redirect('/forgot');
        }

        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

        user.save(function(err) {
          done(err, token, user);
        });
      });
    },
    function(token, user, done) {
      var smtpTransport = nodemailer.createTransport({
        service: 'Gmail',
        auth: {
          user: process.env.MAIL,
          pass: process.env.GMAILPW
        }
      });
      var mailOptions = {
        to: user.username,
        from: process.env.MAIL,
        subject: 'MyNotez SUP Password Reset',
        text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
          'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
          'http://' + req.headers.host + '/reset/' + token + '\n\n' +
          'If you did not request this, please ignore this email and your password will remain unchanged.\n'
      };
      smtpTransport.sendMail(mailOptions, function(err) {
        console.log('mail sent');
        req.flash('success', 'An e-mail has been sent to ' + user.username + ' with further instructions.');
        done(err, 'done');
      });
    }
  ], function(err) {
    if (err) return next(err);
    res.redirect('/forgot');
  });
});

app.get('/reset/:token', function(req, res) {
  User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
    if (!user) {
      req.flash('error', 'Password reset token is invalid or has expired.');
      return res.redirect('/forgot');
    }
    res.render('reset', {token: req.params.token});
  });
});

app.post('/reset/:token', function(req, res) {
  async.waterfall([
    function(done) {
      User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
        if (!user) {
          req.flash('error', 'Password reset token is invalid or has expired.');
          return res.redirect('back');
        }
        if(req.body.password === req.body.confirm) {
          user.setPassword(req.body.password, function(err) {
            user.resetPasswordToken = undefined;
            user.resetPasswordExpires = undefined;

            user.save(function(err) {
              req.logIn(user, function(err) {
                done(err, user);
              });
            });
          })
        } else {
            req.flash("error", "Passwords do not match.");
            return res.redirect('back');
        }
      });
    },
    function(user, done) {
      var smtpTransport = nodemailer.createTransport({
        service: 'Gmail',
        auth: {
          user: process.env.MAIL,
          pass: process.env.GMAILPW
        }
      });
      var mailOptions = {
        to: user.username,
        from: process.env.MAIL,
        subject: 'Your password has been changed',
        text: 'Hello,\n\n' +
          'This is a confirmation that the password for your account ' + user.username + ' has just been changed.\n'
      };
      smtpTransport.sendMail(mailOptions, function(err) {
        req.flash('success', 'Success! Your password has been changed.');
        done(err);
      });
    }
  ], function(err) {
    res.redirect('/login');
  });
});





// *****************************************************Auth End*************************************************
let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}

app.listen(port,(req,res)=>{
  console.log('Listening on port 3000');
});



app.get("*",function(req,res){
  res.render("error");
});

