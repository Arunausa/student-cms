/**
 * Advanced Student Management System
 * Single-file MVC server (models, services, controllers, routes).
 * Deployable as: server.js + package.json + views/login.ejs + views/app.ejs
 *
 * Required env: MONGODB_URI
 * Optional:      PORT (default 3000), SESSION_SECRET, NODE_ENV
 */

'use strict';

require('dotenv').config();

const path = require('path');
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const compression = require('compression');
const cookieParser = require('cookie-parser');
const methodOverride = require('method-override');
const rateLimit = require('express-rate-limit');

/* ====================================================================== */
/* CONFIG                                                                 */
/* ====================================================================== */

const PORT = parseInt(process.env.PORT, 10) || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const SESSION_SECRET =
  process.env.SESSION_SECRET || 'sms-dev-secret-change-me-in-production';
const IS_PROD = process.env.NODE_ENV === 'production';

if (!MONGODB_URI) {
  console.error('FATAL: MONGODB_URI environment variable is required.');
  process.exit(1);
}

/* ====================================================================== */
/* MONGOOSE CONNECTION                                                    */
/* ====================================================================== */

mongoose.set('strictQuery', true);

mongoose
  .connect(MONGODB_URI, {
    serverSelectionTimeoutMS: 15000,
    maxPoolSize: 25,
  })
  .then(() => console.log('MongoDB connected'))
  .catch((err) => {
    console.error('MongoDB connection error:', err.message);
    process.exit(1);
  });

/* ====================================================================== */
/* MODELS                                                                 */
/* ====================================================================== */

const { Schema, model, Types } = mongoose;

const ROLES = Object.freeze({
  ADMIN: 'admin',
  TEACHER: 'teacher',
  STUDENT: 'student',
});

const userSchema = new Schema(
  {
    name: { type: String, required: true, trim: true },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    passwordHash: { type: String, required: true },
    role: {
      type: String,
      enum: Object.values(ROLES),
      required: true,
      index: true,
    },
    rollNo: { type: String, trim: true, default: null },
    course: { type: Types.ObjectId, ref: 'Course', default: null },
    phone: { type: String, trim: true, default: '' },
    avatar: { type: String, default: '' },
    active: { type: Boolean, default: true },
  },
  { timestamps: true }
);

userSchema.methods.verifyPassword = function verifyPassword(plain) {
  return bcrypt.compare(plain, this.passwordHash);
};

userSchema.statics.hashPassword = function hashPassword(plain) {
  return bcrypt.hash(plain, 10);
};

const courseSchema = new Schema(
  {
    name: { type: String, required: true, trim: true, unique: true },
    code: { type: String, required: true, trim: true, unique: true, uppercase: true },
    description: { type: String, default: '' },
    durationYears: { type: Number, default: 3, min: 1, max: 6 },
    active: { type: Boolean, default: true },
  },
  { timestamps: true }
);

const subjectSchema = new Schema(
  {
    name: { type: String, required: true, trim: true },
    code: { type: String, required: true, trim: true, uppercase: true },
    course: { type: Types.ObjectId, ref: 'Course', required: true, index: true },
    teacher: { type: Types.ObjectId, ref: 'User', default: null },
    credits: { type: Number, default: 3, min: 1, max: 10 },
    description: { type: String, default: '' },
  },
  { timestamps: true }
);
subjectSchema.index({ code: 1, course: 1 }, { unique: true });

const attendanceSchema = new Schema(
  {
    student: { type: Types.ObjectId, ref: 'User', required: true, index: true },
    subject: { type: Types.ObjectId, ref: 'Subject', required: true, index: true },
    date: { type: Date, required: true, index: true },
    status: {
      type: String,
      enum: ['present', 'absent', 'late', 'excused'],
      default: 'present',
      required: true,
    },
    markedBy: { type: Types.ObjectId, ref: 'User', required: true },
    remarks: { type: String, default: '', maxlength: 280 },
  },
  { timestamps: true }
);
attendanceSchema.index({ student: 1, subject: 1, date: 1 }, { unique: true });

const scoreSchema = new Schema(
  {
    student: { type: Types.ObjectId, ref: 'User', required: true, index: true },
    subject: { type: Types.ObjectId, ref: 'Subject', required: true, index: true },
    examType: {
      type: String,
      enum: ['quiz', 'midterm', 'final', 'assignment', 'project'],
      required: true,
    },
    marksObtained: { type: Number, required: true, min: 0 },
    totalMarks: { type: Number, required: true, min: 1 },
    remarks: { type: String, default: '' },
    recordedBy: { type: Types.ObjectId, ref: 'User', required: true },
  },
  { timestamps: true }
);

const leaveSchema = new Schema(
  {
    student: { type: Types.ObjectId, ref: 'User', required: true, index: true },
    fromDate: { type: Date, required: true },
    toDate: { type: Date, required: true },
    reason: { type: String, required: true, maxlength: 500 },
    status: {
      type: String,
      enum: ['pending', 'approved', 'rejected'],
      default: 'pending',
      index: true,
    },
    decidedBy: { type: Types.ObjectId, ref: 'User', default: null },
    decisionNote: { type: String, default: '' },
    decidedAt: { type: Date, default: null },
  },
  { timestamps: true }
);

const notificationSchema = new Schema(
  {
    audience: {
      type: String,
      enum: ['all', 'admins', 'teachers', 'students', 'role'],
      default: 'all',
      index: true,
    },
    role: { type: String, enum: Object.values(ROLES), default: null },
    title: { type: String, required: true, trim: true, maxlength: 140 },
    body: { type: String, default: '' },
    createdBy: { type: Types.ObjectId, ref: 'User', required: true },
    reads: [{ type: Types.ObjectId, ref: 'User' }],
  },
  { timestamps: true }
);

const feedbackSchema = new Schema(
  {
    author: { type: Types.ObjectId, ref: 'User', required: true, index: true },
    category: {
      type: String,
      enum: ['bug', 'feature', 'content', 'teacher', 'general'],
      default: 'general',
    },
    subject: { type: String, required: true, trim: true, maxlength: 140 },
    body: { type: String, required: true, maxlength: 2000 },
    rating: { type: Number, min: 1, max: 5, default: null },
    status: {
      type: String,
      enum: ['open', 'reviewed', 'resolved', 'dismissed'],
      default: 'open',
      index: true,
    },
    response: { type: String, default: '' },
    respondedBy: { type: Types.ObjectId, ref: 'User', default: null },
  },
  { timestamps: true }
);

const User = model('User', userSchema);
const Course = model('Course', courseSchema);
const Subject = model('Subject', subjectSchema);
const Attendance = model('Attendance', attendanceSchema);
const Score = model('Score', scoreSchema);
const Leave = model('Leave', leaveSchema);
const Notification = model('Notification', notificationSchema);
const Feedback = model('Feedback', feedbackSchema);

/* ====================================================================== */
/* APP BOOTSTRAP                                                          */
/* ====================================================================== */

const app = express();

app.set('trust proxy', 1);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        'default-src': ["'self'"],
        'script-src': [
          "'self'",
          "'unsafe-inline'",
          'https://cdn.jsdelivr.net',
        ],
        'style-src': [
          "'self'",
          "'unsafe-inline'",
          'https://cdn.jsdelivr.net',
          'https://fonts.googleapis.com',
        ],
        'font-src': ["'self'", 'https://fonts.gstatic.com', 'https://cdn.jsdelivr.net', 'data:'],
        'img-src': ["'self'", 'data:', 'https:'],
        'connect-src': ["'self'"],
      },
    },
    crossOriginEmbedderPolicy: false,
  })
);
app.use(compression());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(cookieParser());
app.use(methodOverride('_method'));
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1d' }));

app.use(
  session({
    name: 'sms.sid',
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: MONGODB_URI,
      ttl: 60 * 60 * 24 * 14, // 14 days
      touchAfter: 60 * 15,
    }),
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: IS_PROD,
      maxAge: 1000 * 60 * 60 * 24 * 14,
    },
  })
);

app.use((req, res, next) => {
  res.locals.currentUser = req.session.user || null;
  res.locals.flash = req.session.flash || null;
  delete req.session.flash;
  next();
});

/* ====================================================================== */
/* HELPERS                                                                */
/* ====================================================================== */

function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

function setFlash(req, type, message) {
  req.session.flash = { type, message };
}

function requireAuth(req, res, next) {
  if (!req.session.user) {
    if (req.accepts('html')) return res.redirect('/login');
    return res.status(401).json({ error: 'Authentication required' });
  }
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.session.user) return res.status(401).json({ error: 'Authentication required' });
    if (!roles.includes(req.session.user.role)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  };
}

function sanitize(input = '') {
  return String(input).replace(/[<>]/g, (m) => (m === '<' ? '&lt;' : '&gt;'));
}

function parseDate(value, fallback = new Date()) {
  if (!value) return fallback;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? fallback : d;
}

function startOfDay(d = new Date()) {
  const x = new Date(d);
  x.setHours(0, 0, 0, 0);
  return x;
}

function endOfDay(d = new Date()) {
  const x = new Date(d);
  x.setHours(23, 59, 59, 999);
  return x;
}

function isValidObjectId(id) {
  return Types.ObjectId.isValid(id) && String(new Types.ObjectId(id)) === String(id);
}

function userToClient(u) {
  if (!u) return null;
  return {
    id: u._id,
    name: u.name,
    email: u.email,
    role: u.role,
    rollNo: u.rollNo,
    course: u.course,
    phone: u.phone,
    avatar: u.avatar,
    active: u.active,
    createdAt: u.createdAt,
  };
}

/* ====================================================================== */
/* SEED                                                                   */
/* ====================================================================== */

async function seed() {
  const userCount = await User.countDocuments();
  if (userCount > 0) return;

  console.log('Seeding initial data...');

  const [adminHash, teacherHash, studentHash] = await Promise.all([
    User.hashPassword('admin123'),
    User.hashPassword('teacher123'),
    User.hashPassword('student123'),
  ]);

  const course = await Course.create({
    name: 'Bachelor of Computer Science',
    code: 'BCS',
    description: 'Four-year undergraduate CS program.',
    durationYears: 4,
  });

  const admin = await User.create({
    name: 'System Admin',
    email: 'admin@sms.local',
    passwordHash: adminHash,
    role: ROLES.ADMIN,
  });

  const teacher = await User.create({
    name: 'Dr. Ada Lovelace',
    email: 'teacher@sms.local',
    passwordHash: teacherHash,
    role: ROLES.TEACHER,
    course: course._id,
    phone: '+1-555-0100',
  });

  const student = await User.create({
    name: 'Alan Turing',
    email: 'student@sms.local',
    passwordHash: studentHash,
    role: ROLES.STUDENT,
    course: course._id,
    rollNo: 'BCS-2026-001',
    phone: '+1-555-0200',
  });

  const [algorithms, databases] = await Subject.create([
    {
      name: 'Algorithms',
      code: 'CS301',
      course: course._id,
      teacher: teacher._id,
      credits: 4,
      description: 'Design and analysis of algorithms.',
    },
    {
      name: 'Databases',
      code: 'CS302',
      course: course._id,
      teacher: teacher._id,
      credits: 3,
      description: 'Relational databases and SQL.',
    },
  ]);

  const today = startOfDay();
  await Attendance.create([
    { student: student._id, subject: algorithms._id, date: today, status: 'present', markedBy: teacher._id },
    { student: student._id, subject: databases._id, date: today, status: 'present', markedBy: teacher._id },
  ]);

  await Score.create([
    {
      student: student._id,
      subject: algorithms._id,
      examType: 'midterm',
      marksObtained: 84,
      totalMarks: 100,
      recordedBy: teacher._id,
    },
    {
      student: student._id,
      subject: databases._id,
      examType: 'assignment',
      marksObtained: 18,
      totalMarks: 20,
      recordedBy: teacher._id,
    },
  ]);

  await Notification.create({
    audience: 'all',
    title: 'Welcome to the Student Management System',
    body: 'Explore the dashboard, mark attendance, and submit feedback.',
    createdBy: admin._id,
  });

  console.log('Seed complete. Demo logins:');
  console.log('  admin@sms.local   / admin123');
  console.log('  teacher@sms.local / teacher123');
  console.log('  student@sms.local / student123');
}

/* ====================================================================== */
/* AUTH ROUTES                                                            */
/* ====================================================================== */

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    setFlash(req, 'danger', 'Too many login attempts. Please try again later.');
    req.session.save(() => res.redirect('/login'));
  },
});

app.get(
  '/login',
  asyncHandler(async (req, res) => {
    if (req.session.user) return res.redirect('/');
    res.render('login', { flash: res.locals.flash });
  })
);

app.post(
  '/login',
  loginLimiter,
  asyncHandler(async (req, res) => {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    if (!email || !password) {
      setFlash(req, 'danger', 'Email and password are required.');
      return res.redirect('/login');
    }

    const user = await User.findOne({ email });
    if (!user || !user.active) {
      setFlash(req, 'danger', 'Invalid credentials.');
      return res.redirect('/login');
    }

    const ok = await user.verifyPassword(password);
    if (!ok) {
      setFlash(req, 'danger', 'Invalid credentials.');
      return res.redirect('/login');
    }

    req.session.user = userToClient(user);
    setFlash(req, 'success', `Welcome back, ${user.name}.`);
    return res.redirect('/');
  })
);

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

/* ====================================================================== */
/* APP SHELL                                                              */
/* ====================================================================== */

app.get(
  '/',
  requireAuth,
  asyncHandler(async (req, res) => {
    res.render('app', { user: req.session.user });
  })
);

/* ====================================================================== */
/* API: ME                                                                */
/* ====================================================================== */

app.get(
  '/api/me',
  requireAuth,
  asyncHandler(async (req, res) => {
    const u = await User.findById(req.session.user.id);
    if (!u) return res.status(404).json({ error: 'User not found' });
    res.json({ user: userToClient(u) });
  })
);

/* ====================================================================== */
/* API: USERS  (admin)                                                    */
/* ====================================================================== */

app.get(
  '/api/users',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { role, q } = req.query;
    const filter = {};
    if (role && Object.values(ROLES).includes(role)) filter.role = role;
    if (q) {
      const re = new RegExp(String(q).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
      filter.$or = [{ name: re }, { email: re }, { rollNo: re }];
    }
    const users = await User.find(filter).populate('course', 'name code').sort({ createdAt: -1 });
    res.json({ users: users.map(userToClient) });
  })
);

app.post(
  '/api/users',
  requireRole(ROLES.ADMIN),
  asyncHandler(async (req, res) => {
    const { name, email, password, role, rollNo, course, phone } = req.body;
    if (!name || !email || !password || !role) {
      return res.status(400).json({ error: 'name, email, password, role are required' });
    }
    if (!Object.values(ROLES).includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }
    const exists = await User.findOne({ email: String(email).toLowerCase() });
    if (exists) return res.status(409).json({ error: 'Email already in use' });

    const passwordHash = await User.hashPassword(password);
    const user = await User.create({
      name,
      email: String(email).toLowerCase(),
      passwordHash,
      role,
      rollNo: rollNo || null,
      course: course && isValidObjectId(course) ? course : null,
      phone: phone || '',
    });
    res.status(201).json({ user: userToClient(user) });
  })
);

app.put(
  '/api/users/:id',
  requireRole(ROLES.ADMIN),
  asyncHandler(async (req, res) => {
    if (!isValidObjectId(req.params.id)) return res.status(400).json({ error: 'Invalid id' });
    const { name, role, rollNo, course, phone, active, password } = req.body;
    const update = {};
    if (name) update.name = name;
    if (role && Object.values(ROLES).includes(role)) update.role = role;
    if (rollNo !== undefined) update.rollNo = rollNo || null;
    if (course !== undefined) update.course = course && isValidObjectId(course) ? course : null;
    if (phone !== undefined) update.phone = phone;
    if (active !== undefined) update.active = !!active;
    if (password) update.passwordHash = await User.hashPassword(password);

    const user = await User.findByIdAndUpdate(req.params.id, update, { new: true });
    if (!user) return res.status(404).json({ error: 'Not found' });
    res.json({ user: userToClient(user) });
  })
);

app.delete(
  '/api/users/:id',
  requireRole(ROLES.ADMIN),
  asyncHandler(async (req, res) => {
    if (!isValidObjectId(req.params.id)) return res.status(400).json({ error: 'Invalid id' });
    if (String(req.params.id) === String(req.session.user.id)) {
      return res.status(400).json({ error: 'You cannot delete your own account.' });
    }
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  })
);

/* ====================================================================== */
/* API: COURSES                                                           */
/* ====================================================================== */

app.get(
  '/api/courses',
  requireAuth,
  asyncHandler(async (req, res) => {
    const courses = await Course.find().sort({ name: 1 });
    res.json({ courses });
  })
);

app.post(
  '/api/courses',
  requireRole(ROLES.ADMIN),
  asyncHandler(async (req, res) => {
    const { name, code, description, durationYears } = req.body;
    if (!name || !code) return res.status(400).json({ error: 'name and code are required' });
    const course = await Course.create({
      name,
      code: String(code).toUpperCase(),
      description: description || '',
      durationYears: Number(durationYears) || 3,
    });
    res.status(201).json({ course });
  })
);

app.put(
  '/api/courses/:id',
  requireRole(ROLES.ADMIN),
  asyncHandler(async (req, res) => {
    if (!isValidObjectId(req.params.id)) return res.status(400).json({ error: 'Invalid id' });
    const { name, code, description, durationYears, active } = req.body;
    const update = {};
    if (name) update.name = name;
    if (code) update.code = String(code).toUpperCase();
    if (description !== undefined) update.description = description;
    if (durationYears) update.durationYears = Number(durationYears);
    if (active !== undefined) update.active = !!active;
    const course = await Course.findByIdAndUpdate(req.params.id, update, { new: true });
    if (!course) return res.status(404).json({ error: 'Not found' });
    res.json({ course });
  })
);

app.delete(
  '/api/courses/:id',
  requireRole(ROLES.ADMIN),
  asyncHandler(async (req, res) => {
    if (!isValidObjectId(req.params.id)) return res.status(400).json({ error: 'Invalid id' });
    const course = await Course.findByIdAndDelete(req.params.id);
    if (!course) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  })
);

/* ====================================================================== */
/* API: SUBJECTS                                                          */
/* ====================================================================== */

app.get(
  '/api/subjects',
  requireAuth,
  asyncHandler(async (req, res) => {
    const filter = {};
    if (req.query.course && isValidObjectId(req.query.course)) {
      filter.course = req.query.course;
    }
    if (req.query.teacher && isValidObjectId(req.query.teacher)) {
      filter.teacher = req.query.teacher;
    }
    const subjects = await Subject.find(filter)
      .populate('course', 'name code')
      .populate('teacher', 'name email')
      .sort({ code: 1 });
    res.json({ subjects });
  })
);

app.post(
  '/api/subjects',
  requireRole(ROLES.ADMIN, ROLES.TEACHER),
  asyncHandler(async (req, res) => {
    const { name, code, course, teacher, credits, description } = req.body;
    if (!name || !code || !course) {
      return res.status(400).json({ error: 'name, code, course are required' });
    }
    if (!isValidObjectId(course)) return res.status(400).json({ error: 'Invalid course id' });
    const subject = await Subject.create({
      name,
      code: String(code).toUpperCase(),
      course,
      teacher: teacher && isValidObjectId(teacher) ? teacher : null,
      credits: Number(credits) || 3,
      description: description || '',
    });
    res.status(201).json({ subject });
  })
);

app.put(
  '/api/subjects/:id',
  requireRole(ROLES.ADMIN, ROLES.TEACHER),
  asyncHandler(async (req, res) => {
    if (!isValidObjectId(req.params.id)) return res.status(400).json({ error: 'Invalid id' });
    const { name, code, course, teacher, credits, description } = req.body;
    const update = {};
    if (name) update.name = name;
    if (code) update.code = String(code).toUpperCase();
    if (course && isValidObjectId(course)) update.course = course;
    if (teacher !== undefined) update.teacher = teacher && isValidObjectId(teacher) ? teacher : null;
    if (credits) update.credits = Number(credits);
    if (description !== undefined) update.description = description;
    const subject = await Subject.findByIdAndUpdate(req.params.id, update, { new: true });
    if (!subject) return res.status(404).json({ error: 'Not found' });
    res.json({ subject });
  })
);

app.delete(
  '/api/subjects/:id',
  requireRole(ROLES.ADMIN),
  asyncHandler(async (req, res) => {
    if (!isValidObjectId(req.params.id)) return res.status(400).json({ error: 'Invalid id' });
    const subject = await Subject.findByIdAndDelete(req.params.id);
    if (!subject) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  })
);

/* ====================================================================== */
/* API: ATTENDANCE                                                        */
/* ====================================================================== */

app.get(
  '/api/attendance',
  requireAuth,
  asyncHandler(async (req, res) => {
    const me = req.session.user;
    const filter = {};
    if (req.query.subject && isValidObjectId(req.query.subject)) {
      filter.subject = req.query.subject;
    }
    if (req.query.student && isValidObjectId(req.query.student)) {
      filter.student = req.query.student;
    }
    if (req.query.from || req.query.to) {
      filter.date = {};
      if (req.query.from) filter.date.$gte = startOfDay(parseDate(req.query.from));
      if (req.query.to) filter.date.$lte = endOfDay(parseDate(req.query.to));
    }
    if (me.role === ROLES.STUDENT) {
      filter.student = me.id;
    } else if (me.role === ROLES.TEACHER) {
      const mySubjects = await Subject.find({ teacher: me.id }).select('_id');
      const mySubjectIds = mySubjects.map((s) => s._id);
      // Intersect with any subject filter already applied from query params
      if (filter.subject) {
        filter.subject = { $in: mySubjectIds.filter((id) => String(id) === String(filter.subject)) };
      } else {
        filter.subject = { $in: mySubjectIds };
      }
    }
    const records = await Attendance.find(filter)
      .populate('student', 'name email rollNo')
      .populate('subject', 'name code')
      .sort({ date: -1 })
      .limit(500);
    res.json({ records });
  })
);

app.post(
  '/api/attendance',
  requireRole(ROLES.ADMIN, ROLES.TEACHER),
  asyncHandler(async (req, res) => {
    const { student, subject, date, status, remarks } = req.body;
    if (!student || !subject || !date || !status) {
      return res.status(400).json({ error: 'student, subject, date, status required' });
    }
    if (!isValidObjectId(student) || !isValidObjectId(subject)) {
      return res.status(400).json({ error: 'Invalid id' });
    }
    const record = await Attendance.findOneAndUpdate(
      { student, subject, date: startOfDay(parseDate(date)) },
      {
        student,
        subject,
        date: startOfDay(parseDate(date)),
        status,
        remarks: remarks || '',
        markedBy: req.session.user.id,
      },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );
    res.status(201).json({ record });
  })
);

app.delete(
  '/api/attendance/:id',
  requireRole(ROLES.ADMIN, ROLES.TEACHER),
  asyncHandler(async (req, res) => {
    if (!isValidObjectId(req.params.id)) return res.status(400).json({ error: 'Invalid id' });
    const record = await Attendance.findByIdAndDelete(req.params.id);
    if (!record) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  })
);

/* ====================================================================== */
/* API: SCORES                                                            */
/* ====================================================================== */

app.get(
  '/api/scores',
  requireAuth,
  asyncHandler(async (req, res) => {
    const me = req.session.user;
    const filter = {};
    if (req.query.subject && isValidObjectId(req.query.subject)) {
      filter.subject = req.query.subject;
    }
    if (me.role === ROLES.STUDENT) {
      filter.student = me.id;
    } else if (req.query.student && isValidObjectId(req.query.student)) {
      filter.student = req.query.student;
    }
    if (me.role === ROLES.TEACHER) {
      const mySubjects = await Subject.find({ teacher: me.id }).select('_id');
      const mySubjectIds = mySubjects.map((s) => s._id);
      // Intersect with any subject filter already applied from query params
      if (filter.subject) {
        filter.subject = { $in: mySubjectIds.filter((id) => String(id) === String(filter.subject)) };
      } else {
        filter.subject = { $in: mySubjectIds };
      }
    }
    const scores = await Score.find(filter)
      .populate('student', 'name email rollNo')
      .populate('subject', 'name code')
      .sort({ createdAt: -1 })
      .limit(500);
    res.json({ scores });
  })
);

app.post(
  '/api/scores',
  requireRole(ROLES.ADMIN, ROLES.TEACHER),
  asyncHandler(async (req, res) => {
    const { student, subject, examType, marksObtained, totalMarks, remarks } = req.body;
    if (!student || !subject || !examType || marksObtained == null || !totalMarks) {
      return res.status(400).json({ error: 'student, subject, examType, marksObtained, totalMarks required' });
    }
    if (!isValidObjectId(student) || !isValidObjectId(subject)) {
      return res.status(400).json({ error: 'Invalid id' });
    }
    const score = await Score.create({
      student,
      subject,
      examType,
      marksObtained: Number(marksObtained),
      totalMarks: Number(totalMarks),
      remarks: remarks || '',
      recordedBy: req.session.user.id,
    });
    res.status(201).json({ score });
  })
);

app.put(
  '/api/scores/:id',
  requireRole(ROLES.ADMIN, ROLES.TEACHER),
  asyncHandler(async (req, res) => {
    if (!isValidObjectId(req.params.id)) return res.status(400).json({ error: 'Invalid id' });
    const { examType, marksObtained, totalMarks, remarks } = req.body;
    const update = {};
    if (examType) update.examType = examType;
    if (marksObtained != null) update.marksObtained = Number(marksObtained);
    if (totalMarks) update.totalMarks = Number(totalMarks);
    if (remarks !== undefined) update.remarks = remarks;
    const score = await Score.findByIdAndUpdate(req.params.id, update, { new: true });
    if (!score) return res.status(404).json({ error: 'Not found' });
    res.json({ score });
  })
);

app.delete(
  '/api/scores/:id',
  requireRole(ROLES.ADMIN, ROLES.TEACHER),
  asyncHandler(async (req, res) => {
    if (!isValidObjectId(req.params.id)) return res.status(400).json({ error: 'Invalid id' });
    const score = await Score.findByIdAndDelete(req.params.id);
    if (!score) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  })
);

/* ====================================================================== */
/* API: LEAVES                                                            */
/* ====================================================================== */

app.get(
  '/api/leaves',
  requireAuth,
  asyncHandler(async (req, res) => {
    const me = req.session.user;
    const filter = {};
    if (req.query.status) filter.status = req.query.status;
    if (me.role === ROLES.STUDENT) {
      filter.student = me.id;
    } else if (req.query.student && isValidObjectId(req.query.student)) {
      filter.student = req.query.student;
    }
    const leaves = await Leave.find(filter)
      .populate('student', 'name email rollNo')
      .populate('decidedBy', 'name')
      .sort({ createdAt: -1 })
      .limit(500);
    res.json({ leaves });
  })
);

app.post(
  '/api/leaves',
  requireAuth,
  asyncHandler(async (req, res) => {
    const me = req.session.user;
    const studentId =
      me.role === ROLES.STUDENT ? me.id : req.body.student;
    const { fromDate, toDate, reason } = req.body;
    if (!studentId || !fromDate || !toDate || !reason) {
      return res.status(400).json({ error: 'student, fromDate, toDate, reason required' });
    }
    if (!isValidObjectId(studentId)) {
      return res.status(400).json({ error: 'Invalid student id' });
    }
    const leave = await Leave.create({
      student: studentId,
      fromDate: parseDate(fromDate),
      toDate: parseDate(toDate),
      reason,
    });
    res.status(201).json({ leave });
  })
);

app.put(
  '/api/leaves/:id',
  requireRole(ROLES.ADMIN, ROLES.TEACHER),
  asyncHandler(async (req, res) => {
    if (!isValidObjectId(req.params.id)) return res.status(400).json({ error: 'Invalid id' });
    const { status, decisionNote } = req.body;
    if (!['approved', 'rejected'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status. Must be approved or rejected.' });
    }
    const update = {
      status,
      decisionNote: decisionNote || '',
      decidedBy: req.session.user.id,
      decidedAt: new Date(),
    };
    const leave = await Leave.findByIdAndUpdate(req.params.id, update, { new: true });
    if (!leave) return res.status(404).json({ error: 'Not found' });
    res.json({ leave });
  })
);

app.delete(
  '/api/leaves/:id',
  requireAuth,
  asyncHandler(async (req, res) => {
    if (!isValidObjectId(req.params.id)) return res.status(400).json({ error: 'Invalid id' });
    const leave = await Leave.findById(req.params.id);
    if (!leave) return res.status(404).json({ error: 'Not found' });
    const me = req.session.user;
    if (me.role !== ROLES.ADMIN && String(leave.student) !== String(me.id)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    if (leave.status !== 'pending' && me.role !== ROLES.ADMIN) {
      return res.status(400).json({ error: 'Cannot delete a decided leave request' });
    }
    await leave.deleteOne();
    res.json({ ok: true });
  })
);

/* ====================================================================== */
/* API: NOTIFICATIONS                                                     */
/* ====================================================================== */

app.get(
  '/api/notifications',
  requireAuth,
  asyncHandler(async (req, res) => {
    const me = req.session.user;
    const matchAudience = {
      $or: [
        { audience: 'all' },
        { audience: 'admins', role: ROLES.ADMIN },
        { audience: 'teachers', role: ROLES.TEACHER },
        { audience: 'students', role: ROLES.STUDENT },
        { audience: 'role', role: me.role },
      ],
    };
    const items = await Notification.find(matchAudience)
      .sort({ createdAt: -1 })
      .limit(100)
      .populate('createdBy', 'name');
    const unread = items.filter((n) => !n.reads.some((r) => String(r) === String(me.id))).length;
    res.json({ notifications: items, unread });
  })
);

app.post(
  '/api/notifications',
  requireRole(ROLES.ADMIN, ROLES.TEACHER),
  asyncHandler(async (req, res) => {
    const { title, body, audience, role } = req.body;
    if (!title) return res.status(400).json({ error: 'title is required' });
    const allowed = ['all', 'admins', 'teachers', 'students', 'role'];
    const aud = allowed.includes(audience) ? audience : 'all';
    const notif = await Notification.create({
      title,
      body: body || '',
      audience: aud,
      role: aud === 'role' && Object.values(ROLES).includes(role) ? role : null,
      createdBy: req.session.user.id,
    });
    res.status(201).json({ notification: notif });
  })
);

app.delete(
  '/api/notifications/:id',
  requireRole(ROLES.ADMIN, ROLES.TEACHER),
  asyncHandler(async (req, res) => {
    if (!isValidObjectId(req.params.id)) return res.status(400).json({ error: 'Invalid id' });
    const n = await Notification.findByIdAndDelete(req.params.id);
    if (!n) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  })
);

app.post(
  '/api/notifications/:id/read',
  requireAuth,
  asyncHandler(async (req, res) => {
    if (!isValidObjectId(req.params.id)) return res.status(400).json({ error: 'Invalid id' });
    await Notification.updateOne(
      { _id: req.params.id },
      { $addToSet: { reads: req.session.user.id } }
    );
    res.json({ ok: true });
  })
);

/* ====================================================================== */
/* API: FEEDBACK                                                          */
/* ====================================================================== */

app.get(
  '/api/feedback',
  requireAuth,
  asyncHandler(async (req, res) => {
    const me = req.session.user;
    const filter = {};
    if (me.role === ROLES.STUDENT) filter.author = me.id;
    if (req.query.status) filter.status = req.query.status;
    const items = await Feedback.find(filter)
      .populate('author', 'name email role')
      .populate('respondedBy', 'name')
      .sort({ createdAt: -1 })
      .limit(500);
    res.json({ feedback: items });
  })
);

app.post(
  '/api/feedback',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { subject, body, category, rating } = req.body;
    if (!subject || !body) return res.status(400).json({ error: 'subject and body required' });
    const allowedCats = ['bug', 'feature', 'content', 'teacher', 'general'];
    const fb = await Feedback.create({
      author: req.session.user.id,
      subject,
      body,
      category: allowedCats.includes(category) ? category : 'general',
      rating: rating ? Math.max(1, Math.min(5, Number(rating))) : null,
    });
    res.status(201).json({ feedback: fb });
  })
);

app.put(
  '/api/feedback/:id',
  requireRole(ROLES.ADMIN, ROLES.TEACHER),
  asyncHandler(async (req, res) => {
    if (!isValidObjectId(req.params.id)) return res.status(400).json({ error: 'Invalid id' });
    const { status, response } = req.body;
    const allowed = ['open', 'reviewed', 'resolved', 'dismissed'];
    const update = {};
    if (allowed.includes(status)) {
      update.status = status;
      update.respondedBy = req.session.user.id;
    }
    if (response !== undefined) {
      update.response = response;
      update.respondedBy = req.session.user.id;
    }
    const fb = await Feedback.findByIdAndUpdate(req.params.id, update, { new: true });
    if (!fb) return res.status(404).json({ error: 'Not found' });
    res.json({ feedback: fb });
  })
);

app.delete(
  '/api/feedback/:id',
  requireAuth,
  asyncHandler(async (req, res) => {
    if (!isValidObjectId(req.params.id)) return res.status(400).json({ error: 'Invalid id' });
    const fb = await Feedback.findById(req.params.id);
    if (!fb) return res.status(404).json({ error: 'Not found' });
    const me = req.session.user;
    if (me.role !== ROLES.ADMIN && String(fb.author) !== String(me.id)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    await fb.deleteOne();
    res.json({ ok: true });
  })
);

/* ====================================================================== */
/* API: DASHBOARD                                                         */
/* ====================================================================== */

app.get(
  '/api/dashboard',
  requireAuth,
  asyncHandler(async (req, res) => {
    const me = req.session.user;
    const today = startOfDay();
    const sevenDaysAgo = new Date(today);
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 6);

    const baseAttendance = { student: me.id, date: { $gte: sevenDaysAgo, $lte: endOfDay() } };

    const [
      userCount,
      studentCount,
      teacherCount,
      courseCount,
      subjectCount,
      pendingLeaves,
      openFeedback,
      totalNotifications,
    ] = await Promise.all([
      User.countDocuments({}),
      User.countDocuments({ role: ROLES.STUDENT }),
      User.countDocuments({ role: ROLES.TEACHER }),
      Course.countDocuments({}),
      Subject.countDocuments({}),
      Leave.countDocuments({ status: 'pending' }),
      Feedback.countDocuments({ status: 'open' }),
      Notification.countDocuments({}),
    ]);

    let myAttendance = [];
    let myScores = [];
    let myLeaves = [];

    if (me.role === ROLES.STUDENT) {
      myAttendance = await Attendance.find(baseAttendance)
        .populate('subject', 'name code')
        .sort({ date: 1 });
      myScores = await Score.find({ student: me.id })
        .populate('subject', 'name code')
        .sort({ createdAt: -1 })
        .limit(20);
      myLeaves = await Leave.find({ student: me.id }).sort({ createdAt: -1 }).limit(20);
    } else if (me.role === ROLES.TEACHER) {
      const mySubjects = await Subject.find({ teacher: me.id }).select('_id');
      myAttendance = await Attendance.find({
        subject: { $in: mySubjects.map((s) => s._id) },
        date: { $gte: sevenDaysAgo, $lte: endOfDay() },
      })
        .populate('subject', 'name code')
        .populate('student', 'name rollNo');
      myScores = await Score.find({ subject: { $in: mySubjects.map((s) => s._id) } })
        .populate('subject', 'name code')
        .populate('student', 'name rollNo')
        .sort({ createdAt: -1 })
        .limit(20);
    }

    const attendanceByDay = {};
    for (let i = 0; i < 7; i += 1) {
      const d = new Date(sevenDaysAgo);
      d.setDate(d.getDate() + i);
      const key = d.toISOString().slice(0, 10);
      attendanceByDay[key] = { present: 0, absent: 0, late: 0, excused: 0 };
    }
    for (const a of myAttendance) {
      const key = new Date(a.date).toISOString().slice(0, 10);
      if (attendanceByDay[key]) attendanceByDay[key][a.status] += 1;
    }
    const attendanceChart = Object.entries(attendanceByDay).map(([day, v]) => ({ day, ...v }));

    const scoreBySubject = {};
    for (const s of myScores) {
      const name = s.subject ? s.subject.name : 'Unknown';
      if (!scoreBySubject[name]) scoreBySubject[name] = { total: 0, count: 0 };
      scoreBySubject[name].total += (s.marksObtained / s.totalMarks) * 100;
      scoreBySubject[name].count += 1;
    }
    const scoreChart = Object.entries(scoreBySubject).map(([subject, v]) => ({
      subject,
      average: v.count ? Math.round((v.total / v.count) * 10) / 10 : 0,
    }));

    res.json({
      counts: {
        users: userCount,
        students: studentCount,
        teachers: teacherCount,
        courses: courseCount,
        subjects: subjectCount,
        pendingLeaves,
        openFeedback,
        notifications: totalNotifications,
      },
      attendanceChart,
      scoreChart,
      recentAttendance: myAttendance.slice(-10).reverse(),
      recentScores: myScores.slice(0, 6),
      recentLeaves: myLeaves.slice(0, 6),
    });
  })
);

/* ====================================================================== */
/* HEALTH                                                                 */
/* ====================================================================== */

app.get('/healthz', (req, res) => res.json({ ok: true, uptime: process.uptime() }));

/* ====================================================================== */
/* ERROR HANDLER                                                          */
/* ====================================================================== */

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  if (req.accepts('html') && !req.path.startsWith('/api/')) {
    setFlash(req, 'danger', 'Something went wrong. Please try again.');
    return res.redirect(req.session.user ? '/' : '/login');
  }
  res.status(err.status || 500).json({ error: err.message || 'Server error' });
});

app.use((req, res) => {
  if (req.accepts('html')) return res.status(404).render('login', { flash: { type: 'danger', message: 'Page not found' } });
  res.status(404).json({ error: 'Not found' });
});

/* ====================================================================== */
/* START                                                                  */
/* ====================================================================== */

app.listen(PORT, () => {
  console.log(`SMS server listening on :${PORT}`);
  seed().catch((e) => console.error('Seed error:', e));
});
