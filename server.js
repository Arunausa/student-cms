/**
 * Student Management System — server.js
 * Single-file server: models, middleware, routes, appHandler.
 * Deploy on Render.com with MONGODB_URI env var.
 */

'use strict';

const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const mongoose = require('mongoose');

/* ====================================================================== */
/* CONFIG                                                                 */
/* ====================================================================== */

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  console.error('ERROR: MONGODB_URI environment variable is not set.');
  console.error('Please set MONGODB_URI in your Render.com environment variables.');
  process.exit(1);
}

/* ====================================================================== */
/* MONGOOSE MODELS                                                        */
/* ====================================================================== */

const { Schema, model } = mongoose;

const courseSchema = new Schema({
  name: { type: String, required: true }
});

const subjectSchema = new Schema({
  name: { type: String, required: true },
  course_id: { type: Schema.Types.ObjectId, ref: 'Course' }
});

const userSchema = new Schema({
  full_name: { type: String, required: true },
  email: { type: String, required: true },
  password: { type: String, default: '123456' },
  role: { type: String, enum: ['admin', 'staff', 'student'], required: true },
  gender: { type: String },
  address: { type: String },
  profile_pic: { type: String, default: 'default.png' },
  course_id: { type: Schema.Types.ObjectId, ref: 'Course' },
  session_id: { type: String }
});

const attendanceSchema = new Schema({
  student_id: { type: Schema.Types.ObjectId, ref: 'User' },
  subject_id: { type: Schema.Types.ObjectId, ref: 'Subject' },
  course_id: { type: Schema.Types.ObjectId, ref: 'Course' },
  status: { type: String },
  date: { type: String }
});

const scoreSchema = new Schema({
  student_id: { type: Schema.Types.ObjectId, ref: 'User' },
  subject_id: { type: Schema.Types.ObjectId, ref: 'Subject' },
  score: { type: Number }
});

const leaveSchema = new Schema({
  user_id: { type: Schema.Types.ObjectId, ref: 'User' },
  role: { type: String },
  date: { type: String },
  message: { type: String },
  status: { type: String, default: 'Pending' },
  created_at: { type: Date, default: Date.now }
});

const notificationSchema = new Schema({
  message: { type: String },
  type: { type: String },
  created_at: { type: Date, default: Date.now }
});

const feedbackSchema = new Schema({
  student_id: { type: Schema.Types.ObjectId, ref: 'User' },
  message: { type: String },
  created_at: { type: Date, default: Date.now }
});

const Course = model('Course', courseSchema);
const Subject = model('Subject', subjectSchema);
const User = model('User', userSchema);
const Attendance = model('Attendance', attendanceSchema);
const Score = model('Score', scoreSchema);
const Leave = model('Leave', leaveSchema);
const Notification = model('Notification', notificationSchema);
const Feedback = model('Feedback', feedbackSchema);

/* ====================================================================== */
/* INIT ADMIN                                                             */
/* ====================================================================== */

async function initAdmin() {
  try {
    const existing = await User.findOne({ role: 'admin' });
    if (!existing) {
      await User.create({
        full_name: 'Administrator',
        email: 'admin@gmail.com',
        password: '123456',
        role: 'admin'
      });
      console.log('Default admin created: admin@gmail.com / 123456');
    }
  } catch (err) {
    console.error('Error creating admin:', err.message);
  }
}

/* ====================================================================== */
/* DATABASE CONNECTION                                                    */
/* ====================================================================== */

mongoose.connect(MONGODB_URI)
  .then(() => {
    console.log('MongoDB connected');
    initAdmin();
  })
  .catch((err) => {
    console.error('MongoDB connection error:', err.message);
    process.exit(1);
  });

/* ====================================================================== */
/* EXPRESS APP                                                            */
/* ====================================================================== */

const app = express();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(session({
  secret: 'secret_key_cms',
  resave: false,
  saveUninitialized: true
}));

/* ====================================================================== */
/* MIDDLEWARE                                                              */
/* ====================================================================== */

function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

/* ====================================================================== */
/* AUTH ROUTES                                                            */
/* ====================================================================== */

app.get('/', (req, res) => res.redirect('/app'));

app.get('/login', (req, res) => {
  res.render('login', { error: req.query.error || null });
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email, password });
    if (!user) {
      return res.redirect('/login?error=Invalid credentials');
    }
    req.session.user = user;
    return res.redirect('/app?page=dashboard');
  } catch (err) {
    console.error('Login error:', err);
    return res.redirect('/login?error=Database Error');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

/* ====================================================================== */
/* APP HANDLER — single handler for GET & POST /app                       */
/* ====================================================================== */

async function appHandler(req, res) {
  try {
    let success_msg = req.query.msg || null;
    const page = req.query.page || 'dashboard';
    const user = req.session.user;

    /* ---- DELETE via GET query params ---- */
    if (req.query.delete && req.query.table && req.query.id) {
      const { table, id } = req.query;
      try {
        if (table === 'courses') await Course.findByIdAndDelete(id);
        else if (table === 'subjects') await Subject.findByIdAndDelete(id);
        else if (table === 'staff' || table === 'students') await User.findByIdAndDelete(id);
      } catch (delErr) {
        console.error('Delete error:', delErr);
      }
      return res.redirect(`/app?page=${req.query.page || page}&msg=Record deleted successfully.`);
    }

    /* ---- POST actions ---- */
    if (req.method === 'POST') {
      const action = req.body.action;

      switch (action) {
        case 'add_course': {
          await Course.create({ name: req.body.name });
          success_msg = 'Course added successfully.';
          break;
        }
        case 'add_subject': {
          await Subject.create({ name: req.body.name, course_id: req.body.course_id });
          success_msg = 'Subject added successfully.';
          break;
        }
        case 'add_staff': {
          const staffData = { ...req.body, role: 'staff' };
          delete staffData.action;
          await User.create(staffData);
          success_msg = 'Staff member added successfully.';
          break;
        }
        case 'add_student': {
          const studentData = { ...req.body, role: 'student' };
          delete studentData.action;
          await User.create(studentData);
          success_msg = 'Student added successfully.';
          break;
        }
        case 'save_attendance': {
          const { date, course_id, subject_id, attendance } = req.body;
          await Attendance.deleteMany({ date, subject_id, course_id });
          if (attendance && typeof attendance === 'object') {
            const keys = Object.keys(attendance);
            for (const studentId of keys) {
              await Attendance.create({
                student_id: studentId,
                subject_id,
                course_id,
                date,
                status: attendance[studentId]
              });
            }
          }
          success_msg = 'Attendance saved successfully.';
          break;
        }
        case 'save_scores': {
          const { subject_id, score } = req.body;
          if (score && typeof score === 'object') {
            const keys = Object.keys(score);
            for (const studentId of keys) {
              if (score[studentId] !== '' && score[studentId] != null) {
                await Score.findOneAndUpdate(
                  { student_id: studentId, subject_id },
                  { score: score[studentId] },
                  { upsert: true, new: true }
                );
              }
            }
          }
          success_msg = 'Scores saved successfully.';
          break;
        }
        case 'apply_leave': {
          await Leave.create({
            user_id: user._id,
            role: user.role,
            date: req.body.date,
            message: req.body.message
          });
          success_msg = 'Leave application submitted.';
          break;
        }
        case 'update_leave': {
          await Leave.findByIdAndUpdate(req.body.leave_id, { status: req.body.status });
          success_msg = `Leave ${req.body.status.toLowerCase()}.`;
          break;
        }
        case 'send_notification': {
          await Notification.create({ message: req.body.message, type: req.body.type });
          success_msg = 'Notification sent successfully.';
          break;
        }
        case 'send_feedback': {
          await Feedback.create({ student_id: user._id, message: req.body.message });
          success_msg = 'Feedback submitted. Thank you!';
          break;
        }
        default:
          success_msg = 'Unknown action.';
      }

      return res.redirect(`/app?page=${page}&msg=${encodeURIComponent(success_msg)}`);
    }

    /* ---- GET: build data object ---- */
    const data = {
      user,
      page,
      success_msg,
      fetched_students: [],
      exam_students: [],
      existing_scores: {},
      existing_attendance: {},
      fetch_date: null,
      fetch_course: null,
      fetch_subject: null,
    };

    // Always fetch
    data.courses = await Course.find();
    data.subjects = await Subject.find().populate('course_id');

    /* ---- Page-specific queries ---- */
    if (page === 'dashboard') {
      data.total_students = await User.countDocuments({ role: 'student' });
      data.total_staff = await User.countDocuments({ role: 'staff' });
      data.total_courses = await Course.countDocuments();
      data.total_subjects = await Subject.countDocuments();
      data.att_count = await Attendance.countDocuments();
      if (user.role === 'student') {
        data.total_present = await Attendance.countDocuments({ student_id: user._id, status: 'Present' });
        data.total_total = await Attendance.countDocuments({ student_id: user._id });
      }
    }

    if (page === 'manage_staff') {
      data.staffs = await User.find({ role: 'staff' });
    }

    if (page === 'manage_students') {
      data.students = await User.find({ role: 'student' }).populate('course_id');
    }

    if (page === 'manage_attendance' || page === 'take_attendance') {
      if (req.query.fetch_course && req.query.fetch_date && req.query.fetch_subject) {
        data.fetch_date = req.query.fetch_date;
        data.fetch_course = req.query.fetch_course;
        data.fetch_subject = req.query.fetch_subject;
        data.fetched_students = await User.find({ role: 'student', course_id: req.query.fetch_course });
        const existingAtt = await Attendance.find({
          date: req.query.fetch_date,
          subject_id: req.query.fetch_subject,
          course_id: req.query.fetch_course
        });
        const attMap = {};
        existingAtt.forEach((a) => { attMap[a.student_id.toString()] = a.status; });
        data.existing_attendance = attMap;
      }
    }

    if (page === 'manage_exams') {
      if (req.query.fetch_course && req.query.fetch_subject) {
        data.fetch_course = req.query.fetch_course;
        data.fetch_subject = req.query.fetch_subject;
        data.exam_students = await User.find({ role: 'student', course_id: req.query.fetch_course });
        const existingScores = await Score.find({ subject_id: req.query.fetch_subject });
        const scoreMap = {};
        existingScores.forEach((s) => { scoreMap[s.student_id.toString()] = s.score; });
        data.existing_scores = scoreMap;
      }
    }

    if (page === 'notifications' && user.role === 'admin') {
      data.leaves = await Leave.find().populate('user_id').sort({ created_at: -1 });
    }

    if (page === 'staff_notifs' || page === 'student_notifs') {
      const roleType = user.role === 'staff' ? 'staff' : 'student';
      data.notifs = await Notification.find({ type: roleType }).sort({ created_at: -1 });
    }

    if (page === 'apply_leave') {
      data.my_leaves = await Leave.find({ user_id: user._id }).sort({ created_at: -1 });
    }

    if (page === 'view_attendance' && user.role === 'staff') {
      data.logs = await Attendance.find()
        .populate('student_id')
        .populate('subject_id')
        .sort({ date: -1 })
        .limit(50);
    }

    if (page === 'my_attendance' && user.role === 'student') {
      data.my_att = await Attendance.find({ student_id: user._id })
        .populate('subject_id')
        .sort({ date: -1 });
    }

    if (page === 'exam_results' && user.role === 'student') {
      data.scores = await Score.find({ student_id: user._id }).populate('subject_id');
    }

    res.render('app', data);

  } catch (err) {
    console.error('appHandler error:', err);
    res.status(500).send('An error occurred while loading the page.');
  }
}

app.get('/app', requireAuth, appHandler);
app.post('/app', requireAuth, appHandler);

/* ====================================================================== */
/* 404 CATCH-ALL                                                          */
/* ====================================================================== */

app.use((req, res) => {
  res.status(404).send(`Route Not Found: ${req.method} ${req.url}`);
});

/* ====================================================================== */
/* START SERVER                                                           */
/* ====================================================================== */

app.listen(PORT, '0.0.0.0', () => {
  console.log(`SMS server running on http://0.0.0.0:${PORT}`);
});
