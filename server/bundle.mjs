import passportJWT from '/opt/nodejs/passport-jwt';
import passport from 'passport';
import mongoose from 'mongoose';
import validate from 'mongoose-validator';
import uniqid from 'uniqid';
import bcrypt from 'bcryptjs';
import rateLimit from 'express-rate-limit';
import aqp from 'api-query-params';
import slugify from 'slugify';
import S3 from 'aws-sdk/clients/s3.js';
import 'mime';
import jwt from 'jsonwebtoken';
import { makeHandler } from '@macchina/server-core/index.js';

const constants = {
  ROLES: {
    ADMIN : 'ADMIN',
    EDITOR: 'EDITOR',
    USER  : 'USER',
  },
  POST_STATES: {
    DRAFT    : 'DRAFT',
    PUBLISHED: 'PUBLISHED',
    DISABLED : 'DISABLED'
  }
};

// User schema
///////////////////////////////////////////////////////////////////////////////
const userSchemaBase = {
  username: {
    type: String,
    unique: false,
    required: [true,"Username is required."],
    validate: [validate({
      validator: "isLength",
      arguments: [3,50],
      message: "Name should be between {ARGS[0]} and {ARGS[1]} characters"
    }), validate({
      validator: "isAlphanumeric",
      passIfEmpty: true,
      message: "Name should contain alpha-numeric characters only"
    })]
  },
  email: {
    type: String,
    unique: true,
    lowercase: true,
    trim: true,
    required: [true,"Email is required."],
    validate: [validate({
      validator: "isEmail",
      message: "Please enter a valid email"
    }), validate({
      validator: "isLength",
      only: "server",
      arguments: [4,100],
      message: "Email should be between {ARGS[0]} and {ARGS[1]} characters"
    })]
  },
  password: {
    type: String,
    trim: true,
    required: [true,"Password is required."],
    validate: [validate({
      validator: "isLength",
      arguments: [8,40],
      message: "Password should be between {ARGS[0]} and {ARGS[1]} characters"
    })]
  },
  imagepath: {
    type: String,
    default: uniqid()
  },
  joined: {
    type: Date,
    default: Date.now
  },
  verified: {
    type: Boolean,
    default: false
  },
  roles: {
    type: [String],
    default: constants.ROLES.USER
  },
  liked: {
    type: [mongoose.Schema.Types.ObjectId],
    default: [],
    ref: "Post"
  },
  messages: {
    type: [mongoose.Schema.Types.ObjectId],
    default: [],
    ref: "Message"
  },
  
};

const userSchema = new mongoose.Schema(userSchemaBase);

const hooks$1 = {
  pre: {
    save: function (next) {
      if (this.isModified('imagepath')) {
        return next()
      }

      // only run this if we're messing with the password field, or else bcrypt
      // will on all saves!
      if (!this.isModified('password')) {
        return next()
      }

      bcrypt.genSalt(10, (err, salt) => {
        if (err) {
          console.log('ERR:', err);
          return next(err)
        }
        bcrypt.hash(this.password, salt, (err, hash) => {
          if (err) {
            console.log('BCRYPT ERR:', err);
            return next(err)
          }
          this.password = hash;
          // console.log('newpass', this.password)
          next();
        });
      });
    }
  }
};

// hooks
///////////////////////////////////////////////////////////////////////////////
for (let hook in hooks$1) {
  for (let hookmethod in hooks$1[hook]) {
    userSchema[hook](hookmethod, hooks$1[hook][hookmethod]);
  }
}

const User = mongoose.model('User', userSchema);

const setupPassport = (app) => {
  // passport & jwt config
  const {
    Strategy: JWTStrategy,
    ExtractJwt: ExtractJWT,
  } = passportJWT;

  // define passport jwt strategy
  const opts = {};
  opts.jwtFromRequest = ExtractJWT.fromAuthHeaderWithScheme('Bearer');
  opts.secretOrKey = process.env.SECRET;
  const passportJWTStrategy = new JWTStrategy(opts, function(jwtPayload, done) {
    // retrieve mail from jwt payload
    // console.log("** payload:", jwtPayload)
    const id = jwtPayload._id;

    // if mail exist in database then authentication succeed
    User.findById(id, '-password', (error, user) => {
      if (error) {
        console.log("Passport error:", error);
        return done(error, false);
      } else {
        if (user) {
          done(null, user);
        } else {
          done(null, false);
        }
      }
    });
  });

  // token strategy
  passport.use(passportJWTStrategy);

  app.use(passport.initialize());

  const auth = passport.authenticate("jwt", { session: false });

  return auth
};

// Comment schema
///////////////////////////////////////////////////////////////////////////////
const commentSchemaBase = {
  body: {
    type: String,
    unique: false,
    required: [true,"Title is required."],
    validate: [validate({
      validator: "isLength",
      arguments: [3,500],
      message: "Comment should be between {ARGS[0]} and {ARGS[1]} characters"
    })]
  },
  created: {
    type: Date,
    default: Date.now
  },
  edited: {
    type: Date,
    default: Date.now
  },
  deleted: {
    type: Boolean,
    select: false,
    default: false
  },
  author: {
    type: String,
    required: true,
    ref: "User"
  },
  post: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: "Post"
  },
  
};

const commentSchema = new mongoose.Schema(commentSchemaBase);

const Comment = mongoose.model('Comment', commentSchema);

const allowQueryBase = ['filter','skip','limit','sort','fields','populate'];
// methods
///////////////////////////////////////////////////////////////////////////////
const methods$5 = {
  create: async (req, res, next) => {
    try {
      let   body    = req.body;
      let  bodyKeys = Object.keys(body);
      
      const user    = req.user;
      if (!user) {
        return res.status(400).send({errors: {auth: {message: 'User must be logged in.'}}})
      }
      
      const allowKeys = [
        "body",
        "post",
      ];
      for (let key in bodyKeys) {
        if (!allowKeys.includes(key)) {
          delete body[key];
        }
      }
      
      
      body = {
        ...body,
        author: user.username,
        edited: Date.now(),
        created: Date.now(),
      };

      const created = await new Comment(body).save();

      return res.status(200).send(created.toObject())
    } catch(err) {
      console.log('** ERROR **: Unknown error on Comment.create', err);
      return res.status(400).send({errors: {unknown: {message: 'Unknown error.'}}})
    }
  },

  find: async (req, res, next) => {
    try {
      let  query = req.query;
      
      
      const allowedVals = allowQueryBase.concat(["post"]);
      for (let key in query) {
        if (!allowedVals.includes(key)) {
          return res.status(400).send({errors: {auth: {message: 'Unauthorized key:'+key}}})
        }
      }
      const requiredVals = ["post"];
      for (let key of requiredVals) {
        if (!Object.keys(query).includes(key)) {
          return res.status(400).send({errors: {auth: {message: 'Required key:'+key}}})
        }
      }
      if (query['limit'] && query['limit'] < 1) {
        return res.status(400).send({errors: {auth: {message: 'Query param:limit below minimum'}}})
      }
      //max
      if (query['limit'] && query['limit'] > 25) {
        return res.status(400).send({errors: {auth: {message: 'Query param:limit above maximum'}}})
      }
      if (!query['limit']) {
        query['limit'] = 25;
      }
      if (!query['sort']) {
        query['sort'] = "-created";
      }
      let { filter,skip,limit,sort,projection,population } = aqp(query);
      
      const found = await Comment
        .find(filter)
        .skip(skip)
        .limit(limit)
        .sort(sort)
        .lean();

      return res.status(200).send(found)
    } catch(err) {
      console.log('** ERROR **: Unknown error on Comment.find', err);
      return res.status(400).send({errors: {unknown: {message: 'Unknown error.'}}})
    }
  },

  findone: async (req, res, next) => {
    try {
      let query     = req.query;
      let queryKeys = Object.keys(query);
      
      
      const requiredVals = ["post"];
      for (let key of requiredVals) {
        if (!Object.keys(query).includes(key)) {
          return res.status(400).send({errors: {auth: {message: 'Required key:'+key}}})
        }
      }
      if (query['limit'] && query['limit'] < 1) {
        return res.status(400).send({errors: {auth: {message: 'Query param:limit below minimum'}}})
      }
      //max
      if (query['limit'] && query['limit'] > 25) {
        return res.status(400).send({errors: {auth: {message: 'Query param:limit above maximum'}}})
      }
      if (!query['limit']) {
        query['limit'] = 25;
      }
      if (!query['sort']) {
        query['sort'] = "-created";
      }
      let { filter,projection,population } = aqp(query);
      
      const found = await Comment.findOne(filter)
                                     .lean();

      if (found == undefined) {
        return res.status(400).send({errors: {unknown: {message: 'Not found.'}}})
      }
      return res.status(200).send(found)
    } catch(err) {
      console.log('** ERROR **: Unknown error on Comment.findone', err);
      return res.status(400).send({errors: {unknown: {message: 'Unknown error.'}}})
    }
  },

  updateone: async (req, res, next) => {
    try {
      let   body    = req.body;
      let  bodyKeys = Object.keys(body);
      let query     = req.query;
      let queryKeys = Object.keys(query);
      
      const user    = req.user;
      if (!user) {
        return res.status(400).send({errors: {auth: {message: 'User must be logged in.'}}})
      }
      // auth
      if (!(
            user.roles.includes(constants.ROLES.USER)
        || user.roles.includes(constants.ROLES.EDITOR)
      )) {
        return res.status(400).send({errors: {auth: {message: 'User not authorized.'}}})
      }
      
      const allowKeys = [
        "body",
      ];
      for (let key in bodyKeys) {
        if (!allowKeys.includes(key)) {
          delete body[key];
        }
      }
      
      
      body = {
        ...body,
        edited: Date.now(),
      };
      
      query["field"] = author;
      query["value"] = user.username;
      if (query['limit'] && query['limit'] < 1) {
        return res.status(400).send({errors: {auth: {message: 'Query param:limit below minimum'}}})
      }
      //max
      if (query['limit'] && query['limit'] > 25) {
        return res.status(400).send({errors: {auth: {message: 'Query param:limit above maximum'}}})
      }
      if (!query['limit']) {
        query['limit'] = 25;
      }
      if (!query['sort']) {
        query['sort'] = "-created";
      }
      let { filter } = aqp(req.query);
      const updated = await Comment.updateOne(filter, body);

      return res.status(200).send(updated)
    } catch(err) {
      console.log('** ERROR **: Unknown error on Comment.updateone', err);
      return res.status(400).send({errors: {unknown: {message: 'Unknown error.'}}})
    }
  },



  count: async (req, res, next) => {
    try {
      let  query = req.query;
      
      
      const requiredVals = ["post"];
      for (let key of requiredVals) {
        if (!Object.keys(query).includes(key)) {
          return res.status(400).send({errors: {auth: {message: 'Required key:'+key}}})
        }
      }
      if (query['limit'] && query['limit'] < 1) {
        return res.status(400).send({errors: {auth: {message: 'Query param:limit below minimum'}}})
      }
      //max
      if (query['limit'] && query['limit'] > 25) {
        return res.status(400).send({errors: {auth: {message: 'Query param:limit above maximum'}}})
      }
      if (!query['limit']) {
        query['limit'] = 25;
      }
      if (!query['sort']) {
        query['sort'] = "-created";
      }
      let { filter } = aqp(query);

      const count = await Comment.count(filter);

      return res.status(200).send(count)
    } catch(err) {
      console.log('** ERROR **: Unknown error on Comment.count', err);
      return res.status(400).send({errors: {unknown: {message: 'Unknown error.'}}})
    }
  },

  delete: async (req, res, next) => {
    try {
      let  query = req.query;
      
      const user    = req.user;
      if (!user) {
        return res.status(400).send({errors: {auth: {message: 'User must be logged in.'}}})
      }
      // auth
      if (!(
            user.roles.includes(constants.ROLES.ADMIN)
      )) {
        return res.status(400).send({errors: {auth: {message: 'User not authorized.'}}})
      }
      
      const requiredVals = ["post"];
      for (let key of requiredVals) {
        if (!Object.keys(query).includes(key)) {
          return res.status(400).send({errors: {auth: {message: 'Required key:'+key}}})
        }
      }
      if (query['limit'] && query['limit'] < 1) {
        return res.status(400).send({errors: {auth: {message: 'Query param:limit below minimum'}}})
      }
      //max
      if (query['limit'] && query['limit'] > 25) {
        return res.status(400).send({errors: {auth: {message: 'Query param:limit above maximum'}}})
      }
      if (!query['limit']) {
        query['limit'] = 25;
      }
      if (!query['sort']) {
        query['sort'] = "-created";
      }
      let { filter } = aqp(query);
      const del = await Comment.deleteOne(filter);

      return res.status(200).send(del)
    } catch(err) {
      console.log('** ERROR **: Unknown error on Comment.delete', err);
      return res.status(400).send({errors: {unknown: {message: 'Unknown error.'}}})
    }
  },


};

const methods$4 = {
  example: async (req, res, next) => {
    const user = req.user;
    if (!user) {
      return null
    } else {
      // const user = await User.findOne({email: user.email}, {password: false, favorites: false})
      return res.send({user})
    }
  },
};

// Post schema
///////////////////////////////////////////////////////////////////////////////
const postSchemaBase = {
  title: {
    type: String,
    unique: false,
    trim: true,
    required: [true,"Title is required."],
    validate: [validate({
      validator: "isLength",
      arguments: [3,120],
      message: "Title should be between {ARGS[0]} and {ARGS[1]} characters"
    })]
  },
  body: {
    type: String,
    unique: false,
    trim: true,
    required: [true,"Post body is required."],
    validate: [validate({
      validator: "isLength",
      arguments: [10,100000],
      message: "Post body should be between {ARGS[0]} and {ARGS[1]} characters"
    })]
  },
  image: {
    type: String,
    required: [true,"Post image is required."]
  },
  slug: {
    type: String
  },
  author: {
    type: String
  },
  edited: {
    type: Date,
    default: Date.now
  },
  created: {
    type: Date,
    default: Date.now
  },
  state: {
    type: [String],
    enum: Object.keys(constants.POST_STATES),
    default: constants.POST_STATES.DRAFT,
    select: false
  },
  liked: {
    type: [mongoose.Schema.Types.ObjectId],
    default: [],
    ref: "Post"
  },
  comments: {
    type: [mongoose.Schema.Types.ObjectId],
    default: [],
    ref: "Comment"
  },
  
};

const postSchema = new mongoose.Schema(postSchemaBase);

new S3();

const hooks = {
  pre: {
    save: function (next) {
      // only run this if we're messing with the password field, or else bcrypt
      // will on all saves!
      if (!this.isModified('title')) {
        return next()
      }

      this.slug = slugify(this.title);
      return next()
    }
  }
};

// hooks
///////////////////////////////////////////////////////////////////////////////
for (let hook in hooks) {
  for (let hookmethod in hooks[hook]) {
    postSchema[hook](hookmethod, hooks[hook][hookmethod]);
  }
}

const Post = mongoose.model('Post', postSchema);

// methods
///////////////////////////////////////////////////////////////////////////////
const methods$3 = {
  create: async (req, res, next) => {
    try {
      let   body    = req.body;
      let  bodyKeys = Object.keys(body);
      
      const user    = req.user;
      if (!user) {
        return res.status(400).send({errors: {auth: {message: 'User must be logged in.'}}})
      }
      
      
      
      body = {
        ...body,
        author: user.username,
      };

      const created = await new Post(body).save();

      return res.status(200).send(created.toObject())
    } catch(err) {
      console.log('** ERROR **: Unknown error on Post.create', err);
      return res.status(400).send({errors: {unknown: {message: 'Unknown error.'}}})
    }
  },

  find: async (req, res, next) => {
    try {
      let  query = req.query;
      
      
      let { filter,skip,limit,sort,projection,population } = aqp(query);
      
      const found = await Post
        .find(filter)
        .lean();

      return res.status(200).send(found)
    } catch(err) {
      console.log('** ERROR **: Unknown error on Post.find', err);
      return res.status(400).send({errors: {unknown: {message: 'Unknown error.'}}})
    }
  },

  findone: async (req, res, next) => {
    try {
      let query     = req.query;
      let queryKeys = Object.keys(query);
      
      
      let { filter,projection,population } = aqp(query);
      
      const found = await Post.findOne(filter)
                                     .lean();

      if (found == undefined) {
        return res.status(400).send({errors: {unknown: {message: 'Not found.'}}})
      }
      return res.status(200).send(found)
    } catch(err) {
      console.log('** ERROR **: Unknown error on Post.findone', err);
      return res.status(400).send({errors: {unknown: {message: 'Unknown error.'}}})
    }
  },

  updateone: async (req, res, next) => {
    try {
      let   body    = req.body;
      let  bodyKeys = Object.keys(body);
      let query     = req.query;
      let queryKeys = Object.keys(query);
      
      const user    = req.user;
      if (!user) {
        return res.status(400).send({errors: {auth: {message: 'User must be logged in.'}}})
      }
      // auth
      if (!(
            user.roles.includes(ROLES.USER)
        || user.roles.includes(ROLES.EDITOR)
      )) {
        return res.status(400).send({errors: {auth: {message: 'User not authorized.'}}})
      }
      
      
      
      
      let { filter } = aqp(req.query);
      const updated = await Post.updateOne(filter, body);

      return res.status(200).send(updated)
    } catch(err) {
      console.log('** ERROR **: Unknown error on Post.updateone', err);
      return res.status(400).send({errors: {unknown: {message: 'Unknown error.'}}})
    }
  },



  count: async (req, res, next) => {
    try {
      let  query = req.query;
      
      
      let { filter } = aqp(query);

      const count = await Post.count(filter);

      return res.status(200).send(count)
    } catch(err) {
      console.log('** ERROR **: Unknown error on Post.count', err);
      return res.status(400).send({errors: {unknown: {message: 'Unknown error.'}}})
    }
  },

  delete: async (req, res, next) => {
    try {
      let  query = req.query;
      
      const user    = req.user;
      if (!user) {
        return res.status(400).send({errors: {auth: {message: 'User must be logged in.'}}})
      }
      // auth
      if (!(
            user.roles.includes(ROLES.ADMIN)
      )) {
        return res.status(400).send({errors: {auth: {message: 'User not authorized.'}}})
      }
      
      let { filter } = aqp(query);
      const del = await Post.deleteOne(filter);

      return res.status(200).send(del)
    } catch(err) {
      console.log('** ERROR **: Unknown error on Post.delete', err);
      return res.status(400).send({errors: {unknown: {message: 'Unknown error.'}}})
    }
  },


};

const createPresignedPost = (key, contentType) => {
  const s3 = new S3();
  const params = {
    Expires: 60,
    Bucket: "fpaboim-macchina",
    Conditions: [["content-length-range", 100, 2*1024*1024]], // 100Byte - 2MB
    Fields: {
      "Content-Type": contentType,
      key
    }
  };
  return new Promise(async (resolve, reject) => {
    s3.createPresignedPost(params, (err, data) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(data);
    });
  });
};

const getPresignedPostData = async (ext, type, bucketkey, res) => {
  let name = uniqid() + '.'+ ext;
  const presignedPostData = await createPresignedPost(
    `${bucketkey}/${name}`,
    type
  );

  return res.status(200).send({data: presignedPostData})
};

const methods$2 = {
  signS3: async (req, res, next) => {
    try {
      const user = req.user;
      if (!user || !user.imagepath) {
        return res.status(401).send({errors: {email: {message: 'Error authenticating.'}}})
      }

      const bucketkey = user.imagepath;
      const body = req.body;

      if (!body.name || !body.type) {
        return res.status(401).send({errors: {unknown: {message: 'Missing parameters.'}}})
      }

      let name = body.name;
      let namesplit = name.split('.');
      let ext = namesplit[namesplit.length-1];

      return await getPresignedPostData(ext, body.type, bucketkey, res)
    } catch (e) {
      return res.status(401).send({errors: {unknown: {message: 'Unknown error.'}}})
    }
  },
};

const createToken = (user, secret, expiresIn='2d') => {
  // console.log('CRETE TOKEN USER:', user)
  return jwt.sign({ email: user.email, _id: user._id }, secret, { expiresIn })
};


const methods$1 = {
  getCurrentUser: async (req, res, next) => {
    const user = req.user;
    if (!user) {
      return null
    } else {
      // const user = await User.findOne({email: user.email}, {password: false, favorites: false})
      return res.send({user})
    }
  },

  verifyEmail: async (req, res, next) => {
    const user = await User.findById(req.user.id, '-password').lean();
    if (!user) {
      return res.status(401).send({errors: {email: {message: 'Error refreshing token.'}}})
    }
  },


  refreshToken: async (req, res, next) => {
    const user = await User.findById(req.user.id, '-password').lean();
    if (!user) {
      return res.status(401).send({errors: {email: {message: 'Error refreshing token.'}}})
    }

    return res.status(200).send({ token: createToken(user, process.env.SECRET) })
  },

  signinUser: async (req, res, next) => {
    const {email, password} = req.body;
    // console.log('signing in', email)
    let user = await User.findOne({email}).lean();
    // console.log('signing in user:', user)
    if (!user) {
      return res.status(401).send({errors: {email: {message: 'Email not found.'}}})
    }
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).send({errors: {password: {message: 'Invalid password.'}}})
    }

    delete user.password;
    // console.log('token for:', user)

    const token = createToken(user, process.env.SECRET);

    return res.status(200).send({...user, token})
  },

  signupUser: async (req, res, next) => {
    try {
      console.log('signup');
      // console.log('USER:', email, password)
      const {username, email, password} = req.body;

      const user = await User.findOne({ email }).lean();
      const user2 = await User.findOne({ username }).lean();

      if (user) {
        return res.status(400).send({errors: {email: {message: 'Email already registered.'}}})
      }

      if (user2) {
        return res.status(400).send({errors: {username: {message: 'Username already exists.'}}})
      }

      let newUser = await new User({
        username,
        email,
        password
      }).save();
      newUser=newUser.toObject();
      const token = createToken(newUser, process.env.SECRET);

      return res.status(200).send({...newUser, token})
    } catch(err) {
      console.log('err:', err);
      return res.status(400).json(err)
    }
  }
};

// methods
///////////////////////////////////////////////////////////////////////////////
const methods = {

  find: async (req, res, next) => {
    try {
      let  query = req.query;
      
      const user    = req.user;
      if (!user) {
        return res.status(400).send({errors: {auth: {message: 'User must be logged in.'}}})
      }
      // auth
      if (!(
            user.roles.includes(constants.ROLES.ADMIN)
      )) {
        return res.status(400).send({errors: {auth: {message: 'User not authorized.'}}})
      }
      
      let { filter,skip,limit,sort,projection,population } = aqp(query);
      
      const found = await User
        .find(filter)
        .lean();

      return res.status(200).send(found)
    } catch(err) {
      console.log('** ERROR **: Unknown error on User.find', err);
      return res.status(400).send({errors: {unknown: {message: 'Unknown error.'}}})
    }
  },








};

const CommentController = methods$5;
const PostController = {...methods$3, ...methods$4};
const UploadController = methods$2;
const UserController = {...methods, ...methods$1};


const auth = passport.authenticate("jwt", { session: false });

const apiLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 60 minutes
  message: {errors: [{username: 'Too many attempts.'}]},
  max: 20
});


// 3. Routes
const router = (app) => {
  console.log("Setup routes...");
  app.post("/comment/count",  CommentController.count);
  app.post("/comment/delete", [auth], CommentController.delete);
  app.get("/comment/find",  CommentController.find);
  app.get("/comment/findone",  CommentController.findone);
  app.post("/comment/create", [auth], CommentController.create);
  app.post("/comment/updateone", [auth], CommentController.updateone);
  app.post("/post/count",  PostController.count);
  app.post("/post/delete", [auth], PostController.delete);
  app.get("/post/find",  PostController.find);
  app.get("/post/findone",  PostController.findone);
  app.post("/post/create", [auth,apiLimiter], PostController.create);
  app.post("/post/updateone", [auth], PostController.updateone);
  app.post("/upload/signS3", [auth,apiLimiter], UploadController.signS3);
  app.post("/user/auth/login", [apiLimiter], UserController.signinUser);
  app.post("/user/auth/signup", [apiLimiter], UserController.signupUser);
  app.post("/user/auth/refreshtoken", [apiLimiter], UserController.refreshToken);
  app.post("/user/auth/verifyEmail/:userid/:token", [apiLimiter], UserController.verifyEmail);
  app.post("/user/profile", [auth], UserController.getCurrentUser);
  app.get("/user/find", [auth], UserController.find);
};

const macchina_options = {
  whitelist: [
    'https://macchina-svelte-starter.vercel.app',
    'http://macchina-svelte-starter.vercel.app',
    'http://127.0.0.1:3000',
    'http://localhost:3000',
  ]
};

const startApp = makeHandler(router, [setupPassport], macchina_options);

export { startApp as default };
