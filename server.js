require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const multer = require('multer');
const admin = require('firebase-admin');

// Initialize Firebase Admin SDK
const firebaseConfig = JSON.parse(process.env.FIREBASE_CONFIG);
admin.initializeApp({
  credential: admin.credential.cert(firebaseConfig),
  storageBucket: `${firebaseConfig.project_id}.appspot.com`
});

const db = admin.firestore();
const bucket = admin.storage().bucket();

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet());
app.use(cors({
  origin: ['http://localhost:3000', 'https://your-domain.com'],
  credentials: true
}));
app.use(express.json());
app.use(express.static('public'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: { error: 'Too many requests, please try again later.' }
});
app.use('/api/', limiter);

// Multer setup for video uploads (memory storage, then to Firebase)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['video/mp4', 'video/webm', 'video/quicktime'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only MP4, WebM, and MOV are allowed.'));
    }
  }
});

// JWT Authentication Middleware
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: No token provided' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// Helper: Upload video to Firebase Storage
async function uploadVideoToFirebase(file, folder) {
  const timestamp = Date.now();
  const filename = `${folder}/${timestamp}_${file.originalname.replace(/\s/g, '_')}`;
  const fileUpload = bucket.file(filename);
  
  const stream = fileUpload.createWriteStream({
    metadata: { contentType: file.mimetype },
    resumable: false
  });

  return new Promise((resolve, reject) => {
    stream.on('error', reject);
    stream.on('finish', async () => {
      await fileUpload.makePublic();
      const publicUrl = `https://storage.googleapis.com/${bucket.name}/${filename}`;
      resolve(publicUrl);
    });
    stream.end(file.buffer);
  });
}

// ========== API ROUTES ==========

// POST /api/login
app.post('/api/login',
  body('username').trim().notEmpty(),
  body('password').notEmpty(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const { username, password } = req.body;
    if (username === process.env.ADMIN_USER && password === process.env.ADMIN_PASS) {
      const token = jwt.sign(
        { username, role: 'admin' },
        process.env.JWT_SECRET,
        { expiresIn: '8h' }
      );
      return res.json({ token, message: 'Login successful' });
    } else {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
  }
);

// GET /api/signs - Get all approved signs
app.get('/api/signs', async (req, res) => {
  try {
    const { governorate, search } = req.query;
    let query = db.collection('signs');
    
    if (governorate && governorate !== 'all') {
      query = query.where('governorate', '==', governorate);
    }
    
    const snapshot = await query.get();
    let signs = [];
    snapshot.forEach(doc => signs.push({ id: doc.id, ...doc.data() }));
    
    if (search) {
      const searchLower = search.toLowerCase();
      signs = signs.filter(sign => 
        sign.destinationName.toLowerCase().includes(searchLower)
      );
    }
    
    res.json(signs.sort((a, b) => b.createdAt - a.createdAt));
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch signs' });
  }
});

// POST /api/signs - Admin creates sign manually
app.post('/api/signs', authenticateJWT, upload.single('video'), async (req, res) => {
  try {
    const { destinationName, governorate, description } = req.body;
    if (!destinationName || !governorate || !req.file) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    const videoUrl = await uploadVideoToFirebase(req.file, 'signs');
    const newSign = {
      destinationName,
      governorate,
      videoUrl,
      description: description || '',
      createdAt: Date.now()
    };
    
    const docRef = await db.collection('signs').add(newSign);
    res.status(201).json({ id: docRef.id, ...newSign });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create sign' });
  }
});

// PUT /api/signs/:id - Update sign
app.put('/api/signs/:id', authenticateJWT, async (req, res) => {
  try {
    const { id } = req.params;
    const { destinationName, governorate, description } = req.body;
    
    const updateData = {};
    if (destinationName) updateData.destinationName = destinationName;
    if (governorate) updateData.governorate = governorate;
    if (description !== undefined) updateData.description = description;
    
    await db.collection('signs').doc(id).update(updateData);
    res.json({ message: 'Sign updated successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update sign' });
  }
});

// DELETE /api/signs/:id - Delete sign
app.delete('/api/signs/:id', authenticateJWT, async (req, res) => {
  try {
    const { id } = req.params;
    const signDoc = await db.collection('signs').doc(id).get();
    if (!signDoc.exists) {
      return res.status(404).json({ error: 'Sign not found' });
    }
    
    // Delete from Storage (extract filename from URL)
    const videoUrl = signDoc.data().videoUrl;
    const filename = videoUrl.split('/').pop();
    if (filename) {
      try {
        await bucket.file(`signs/${filename}`).delete();
      } catch (e) { console.log('Storage delete error:', e); }
    }
    
    await db.collection('signs').doc(id).delete();
    res.json({ message: 'Sign deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete sign' });
  }
});

// POST /api/submit - User submits new hand signal request
app.post('/api/submit', upload.single('video'), async (req, res) => {
  try {
    const { destinationName, governorate, notes } = req.body;
    if (!destinationName || !governorate || !req.file) {
      return res.status(400).json({ error: 'Destination, governorate and video are required' });
    }
    
    const videoUrl = await uploadVideoToFirebase(req.file, 'submissions');
    const submission = {
      destinationName,
      governorate,
      videoUrl,
      notes: notes || '',
      status: 'pending',
      createdAt: Date.now()
    };
    
    const docRef = await db.collection('submissions').add(submission);
    res.status(201).json({ message: 'Submission received! Awaiting approval.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to submit' });
  }
});

// GET /api/submissions - Admin gets all submissions
app.get('/api/submissions', authenticateJWT, async (req, res) => {
  try {
    const snapshot = await db.collection('submissions').orderBy('createdAt', 'desc').get();
    const submissions = [];
    snapshot.forEach(doc => submissions.push({ id: doc.id, ...doc.data() }));
    res.json(submissions);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch submissions' });
  }
});

// POST /api/submissions/:id/approve - Approve submission
app.post('/api/submissions/:id/approve', authenticateJWT, async (req, res) => {
  try {
    const { id } = req.params;
    const submissionDoc = await db.collection('submissions').doc(id).get();
    if (!submissionDoc.exists) {
      return res.status(404).json({ error: 'Submission not found' });
    }
    
    const data = submissionDoc.data();
    const newSign = {
      destinationName: data.destinationName,
      governorate: data.governorate,
      videoUrl: data.videoUrl,
      description: data.notes || '',
      createdAt: data.createdAt
    };
    
    await db.collection('signs').add(newSign);
    await db.collection('submissions').doc(id).update({ status: 'approved' });
    res.json({ message: 'Submission approved and added to signs' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to approve submission' });
  }
});

// POST /api/submissions/:id/reject - Reject submission
app.post('/api/submissions/:id/reject', authenticateJWT, async (req, res) => {
  try {
    const { id } = req.params;
    await db.collection('submissions').doc(id).update({ status: 'rejected' });
    res.json({ message: 'Submission rejected' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to reject submission' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Eshartak server running on port ${PORT}`);
});