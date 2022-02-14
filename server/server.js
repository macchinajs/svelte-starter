'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var passportJWT = require('passport-jwt');
var passport = require('passport');
var User$1 = require('.fabo/models/User');
var rateLimit = require('express-rate-limit');
var mongoose = require('mongoose');
var validate = require('mongoose-validator');
var aqp = require('api-query-params');
var bcrypt = require('bcryptjs');
var slugify = require('slugify');
var S3 = require('aws-sdk/clients/s3');
var uniqid = require('uniqid');
require('mime');
var jwt = require('jsonwebtoken');

function _interopDefaultLegacy (e) { return e && typeof e === 'object' && 'default' in e ? e : { 'default': e }; }

var passportJWT__default = /*#__PURE__*/_interopDefaultLegacy(passportJWT);
var passport__default = /*#__PURE__*/_interopDefaultLegacy(passport);
var User__default = /*#__PURE__*/_interopDefaultLegacy(User$1);
var rateLimit__default = /*#__PURE__*/_interopDefaultLegacy(rateLimit);
var mongoose__default = /*#__PURE__*/_interopDefaultLegacy(mongoose);
var validate__default = /*#__PURE__*/_interopDefaultLegacy(validate);
var aqp__default = /*#__PURE__*/_interopDefaultLegacy(aqp);
var bcrypt__default = /*#__PURE__*/_interopDefaultLegacy(bcrypt);
var slugify__default = /*#__PURE__*/_interopDefaultLegacy(slugify);
var S3__default = /*#__PURE__*/_interopDefaultLegacy(S3);
var uniqid__default = /*#__PURE__*/_interopDefaultLegacy(uniqid);
var jwt__default = /*#__PURE__*/_interopDefaultLegacy(jwt);

const setupPassport = (app) => {
  // passport & jwt config
  const {
    Strategy: JWTStrategy,
    ExtractJwt: ExtractJWT,
  } = passportJWT__default["default"];

  // define passport jwt strategy
  const opts = {};
  opts.jwtFromRequest = ExtractJWT.fromAuthHeaderWithScheme('Bearer');
  opts.secretOrKey = process.env.SECRET;
  const passportJWTStrategy = new JWTStrategy(opts, function(jwtPayload, done) {
    // retrieve mail from jwt payload
    // console.log("** payload:", jwtPayload)
    const id = jwtPayload._id;

    // if mail exist in database then authentication succeed
    User__default["default"].findById(id, '-password', (error, user) => {
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
  passport__default["default"].use(passportJWTStrategy);

  app.use(passport__default["default"].initialize());

  const auth = passport__default["default"].authenticate("jwt", { session: false });

  return auth
};

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

// Comment schema
///////////////////////////////////////////////////////////////////////////////
var schema$2 = {
  body: {
    type: String,
    unique: false,
    required: [true,"Title is required."],
    validate: [validate__default["default"]({
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
    type: mongoose__default["default"].Schema.Types.ObjectId,
    required: true,
    ref: "Post"
  },
};

const CommentSchema = new mongoose__default["default"].Schema(schema$2);

const Comment = mongoose__default["default"].model('Comment', CommentSchema);

const allowQueryBase = ['filter','skip','limit','sort','fields','populate'];
// methods
///////////////////////////////////////////////////////////////////////////////
const methods$5 = {
  count: async (req, res, next) => {
    try {
      const user = req.user;
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
      let { filter } = aqp__default["default"](query);

      const count = await Comment.count(filter);

      return res.status(200).send(count)
    } catch(err) {
      console.log('** ERROR **: Unknown error on Comment.count', err);
      return res.status(400).send({errors: {unknown: {message: 'Unknown error.'}}})
    }
  },

  delete: async (req, res, next) => {
    try {
      const user = req.user;
      let  query = req.query;

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
      let { filter } = aqp__default["default"](query);
      const del = await Comment.deleteOne(filter);

      return res.status(200).send(del)
    } catch(err) {
      console.log('** ERROR **: Unknown error on Comment.delete', err);
      return res.status(400).send({errors: {unknown: {message: 'Unknown error.'}}})
    }
  },

  find: async (req, res, next) => {
    try {
      const user = req.user;
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
      let { filter,skip,limit,sort,projection,population } = aqp__default["default"](query);
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
      const user    = req.user;
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
      let { filter,projection,population } = aqp__default["default"](query);
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

  create: async (req, res, next) => {
    try {
      const user    = req.user;
      let   body    = req.body;
      let  bodyKeys = Object.keys(body);

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

  updateone: async (req, res, next) => {
    try {
      const user    = req.user;
      let   body    = req.body;
      let  bodyKeys = Object.keys(body);
      let query     = req.query;
      let queryKeys = Object.keys(query);

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

      query["author"] = user.username;
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
      let { filter } = aqp__default["default"](req.query);
      const updated = await Comment.updateOne(filter, body);

      return res.status(200).send(updated)
    } catch(err) {
      console.log('** ERROR **: Unknown error on Comment.updateone', err);
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
var schema$1 = {
  title: {
    type: String,
    unique: false,
    trim: true,
    required: [true,"Title is required."],
    validate: [validate__default["default"]({
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
    validate: [validate__default["default"]({
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
    type: [mongoose__default["default"].Schema.Types.ObjectId],
    default: [],
    ref: "Post"
  },
  comments: {
    type: [mongoose__default["default"].Schema.Types.ObjectId],
    default: [],
    ref: "Comment"
  },
};

new S3__default["default"]();

const hooks$1 = {
  pre: {
    save: function (next) {
      // only run this if we're messing with the password field, or else bcrypt
      // will on all saves!
      if (!this.isModified('title')) {
        return next()
      }

      this.slug = slugify__default["default"](this.title);
      return next()
    }
  }
};

const PostSchema = new mongoose__default["default"].Schema(schema$1);
// hooks
///////////////////////////////////////////////////////////////////////////////
for (let hook in hooks$1) {
  for (let hookmethod in hooks$1[hook]) {
    PostSchema[hook](hookmethod, hooks$1[hook][hookmethod]);
  }
}

const Post = mongoose__default["default"].model('Post', PostSchema);

// methods
///////////////////////////////////////////////////////////////////////////////
const methods$3 = {
  count: async (req, res, next) => {
    try {
      const user = req.user;
      let  query = req.query;


      let { filter } = aqp__default["default"](query);

      const count = await Post.count(filter);

      return res.status(200).send(count)
    } catch(err) {
      console.log('** ERROR **: Unknown error on Post.count', err);
      return res.status(400).send({errors: {unknown: {message: 'Unknown error.'}}})
    }
  },

  delete: async (req, res, next) => {
    try {
      const user = req.user;
      let  query = req.query;

      if (!user) {
        return res.status(400).send({errors: {auth: {message: 'User must be logged in.'}}})
      }
      // auth
      if (!(
            user.roles.includes(ROLES.ADMIN)
      )) {
        return res.status(400).send({errors: {auth: {message: 'User not authorized.'}}})
      }

      let { filter } = aqp__default["default"](query);
      const del = await Post.deleteOne(filter);

      return res.status(200).send(del)
    } catch(err) {
      console.log('** ERROR **: Unknown error on Post.delete', err);
      return res.status(400).send({errors: {unknown: {message: 'Unknown error.'}}})
    }
  },

  find: async (req, res, next) => {
    try {
      const user = req.user;
      let  query = req.query;


      let { filter,skip,limit,sort,projection,population } = aqp__default["default"](query);
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
      const user    = req.user;
      let query     = req.query;
      let queryKeys = Object.keys(query);


      let { filter,projection,population } = aqp__default["default"](query);
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

  create: async (req, res, next) => {
    try {
      const user    = req.user;
      let   body    = req.body;
      let  bodyKeys = Object.keys(body);

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

  updateone: async (req, res, next) => {
    try {
      const user    = req.user;
      let   body    = req.body;
      let  bodyKeys = Object.keys(body);
      let query     = req.query;
      let queryKeys = Object.keys(query);

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




      let { filter } = aqp__default["default"](req.query);
      const updated = await Post.updateOne(filter, body);

      return res.status(200).send(updated)
    } catch(err) {
      console.log('** ERROR **: Unknown error on Post.updateone', err);
      return res.status(400).send({errors: {unknown: {message: 'Unknown error.'}}})
    }
  },


};

const createPresignedPost = (key, contentType) => {
  const s3 = new S3__default["default"]();
  const params = {
    Expires: 60,
    Bucket: "fpaboim-fabo",
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
  let name = uniqid__default["default"]() + '.'+ ext;
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

// User schema
///////////////////////////////////////////////////////////////////////////////
var schema = {
  username: {
    type: String,
    unique: false,
    required: [true,"Username is required."],
    validate: [validate__default["default"]({
      validator: "isLength",
      arguments: [3,50],
      message: "Name should be between {ARGS[0]} and {ARGS[1]} characters"
    }), validate__default["default"]({
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
    validate: [validate__default["default"]({
      validator: "isEmail",
      message: "Please enter a valid email"
    }), validate__default["default"]({
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
    validate: [validate__default["default"]({
      validator: "isLength",
      arguments: [8,40],
      message: "Password should be between {ARGS[0]} and {ARGS[1]} characters"
    })]
  },
  imagepath: {
    type: String,
    default: uniqid__default["default"]()
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
    type: [mongoose__default["default"].Schema.Types.ObjectId],
    default: [],
    ref: "Post"
  },
  messages: {
    type: [mongoose__default["default"].Schema.Types.ObjectId],
    default: [],
    ref: "Message"
  },
};

const hooks = {
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

      bcrypt__default["default"].genSalt(10, (err, salt) => {
        if (err) {
          console.log('ERR:', err);
          return next(err)
        }
        bcrypt__default["default"].hash(this.password, salt, (err, hash) => {
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

const UserSchema = new mongoose__default["default"].Schema(schema);
// hooks
///////////////////////////////////////////////////////////////////////////////
for (let hook in hooks) {
  for (let hookmethod in hooks[hook]) {
    UserSchema[hook](hookmethod, hooks[hook][hookmethod]);
  }
}

const User = mongoose__default["default"].model('User', UserSchema);

const createToken = (user, secret, expiresIn='2d') => {
  // console.log('CRETE TOKEN USER:', user)
  return jwt__default["default"].sign({ email: user.email, _id: user._id }, secret, { expiresIn })
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
    const isValidPassword = await bcrypt__default["default"].compare(password, user.password);
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
      const user = req.user;
      let  query = req.query;

      if (!user) {
        return res.status(400).send({errors: {auth: {message: 'User must be logged in.'}}})
      }
      // auth
      if (!(
            user.roles.includes(constants.ROLES.ADMIN)
      )) {
        return res.status(400).send({errors: {auth: {message: 'User not authorized.'}}})
      }

      let { filter,skip,limit,sort,projection,population } = aqp__default["default"](query);
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


const auth = passport__default["default"].authenticate("jwt", { session: false });

const apiLimiter = rateLimit__default["default"]({
  windowMs: 60 * 60 * 1000, // 60 minutes
  message: {errors: [{username: 'Too many attempts.'}]},
  max: 20
});


// 3. Routes
const router = (app) => {
  console.log("Setup routes...");
  app.post("/comment/count",  CommentController.count);
  app.post("/comment/delete", [auth], CommentController.delete);
  app.post("/comment/find",  CommentController.find);
  app.post("/comment/findone",  CommentController.findone);
  app.post("/comment/create", [auth], CommentController.create);
  app.post("/comment/updateone", [auth], CommentController.updateone);
  app.post("/post/count",  PostController.count);
  app.post("/post/delete", [auth], PostController.delete);
  app.post("/post/find",  PostController.find);
  app.post("/post/findone",  PostController.findone);
  app.post("/post/create", [auth,apiLimiter], PostController.create);
  app.post("/post/updateone", [auth], PostController.updateone);
  app.post("/upload/signS3", [auth,apiLimiter], UploadController.signS3);
  app.post("/user/auth/login", [apiLimiter], UserController.signinUser);
  app.post("/user/auth/signup", [apiLimiter], UserController.signupUser);
  app.post("/user/auth/refreshtoken", [apiLimiter], UserController.refreshToken);
  app.post("/user/auth/verifyEmail/:userid/:token", [apiLimiter], UserController.verifyEmail);
  app.post("/user/profile", [auth], UserController.getCurrentUser);
  app.post("/user/find", [auth], UserController.find);
};

const fabo_options = {
  whitelist: [
    'https://fabo-starter.vercel.app',
    'http://fabo-starter.vercel.app',
    'http://192.168.111.3:3000',
    'http://localhost:3000',
  ]
};

const startApp = makeHandler(router, [setupPassport], fabo_options);

exports.startApp = startApp;
