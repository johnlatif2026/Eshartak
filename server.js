require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const multer = require('multer');
const { v2: cloudinary } = require('cloudinary');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const admin = require('firebase-admin');

// Initialize Firebase Admin SDK
const firebaseConfig = JSON.parse(process.env.FIREBASE_CONFIG);
admin.initializeApp({
  credential: admin.credential.cert(firebaseConfig),
});

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const db = admin.firestore();
const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet());
app.use(cors({
  origin: ['http://localhost:3000', 'https://eshartak.vercel.app', 'https://eshartak-ne0lzo5hy-john-latifs-projects.vercel.app'],
  credentials: true
}));
app.use(express.json());
app.use(express.static('public'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, please try again later.' }
});
app.use('/api/', limiter);

// Configure Multer with Cloudinary storage for videos
const videoStorage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'eshartak',
    resource_type: 'video',
    allowed_formats: ['mp4', 'webm', 'mov', 'avi'],
    transformation: [
      { quality: 'auto' },
      { fetch_format: 'auto' }
    ]
  }
});

const upload = multer({
  storage: videoStorage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['video/mp4', 'video/webm', 'video/quicktime', 'video/x-msvideo'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only MP4, WebM, MOV, and AVI are allowed.'));
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
      return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
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
    console.error('Error fetching signs:', err);
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
    
    const videoUrl = req.file.path;
    
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
    console.error(err);
    res.status(500).json({ error: 'Failed to create sign' });
  }
});

// PUT /api/signs/:id - Update sign text fields
app.put('/api/signs/:id', authenticateJWT, async (req, res) => {
  try {
    const { id } = req.params;
    const { destinationName, governorate, description } = req.body;
    
    const updateData = {};
    if (destinationName !== undefined) updateData.destinationName = destinationName;
    if (governorate !== undefined) updateData.governorate = governorate;
    if (description !== undefined) updateData.description = description;
    updateData.updatedAt = Date.now();
    
    await db.collection('signs').doc(id).update(updateData);
    res.json({ message: 'تم تحديث الإشارة بنجاح' });
  } catch (err) {
    console.error('Error updating sign:', err);
    res.status(500).json({ error: 'Failed to update sign' });
  }
});

// PATCH /api/signs/:id/video - Update only video for a sign
app.patch('/api/signs/:id/video', authenticateJWT, upload.single('video'), async (req, res) => {
  try {
    const { id } = req.params;
    
    // Check if sign exists
    const signDoc = await db.collection('signs').doc(id).get();
    if (!signDoc.exists) {
      return res.status(404).json({ error: 'Sign not found' });
    }
    
    // Check if video file is provided
    if (!req.file) {
      return res.status(400).json({ error: 'Video file is required' });
    }
    
    const oldSignData = signDoc.data();
    const oldVideoUrl = oldSignData.videoUrl;
    const newVideoUrl = req.file.path;
    
    // Delete old video from Cloudinary
    if (oldVideoUrl && oldVideoUrl.includes('cloudinary.com')) {
      try {
        const urlParts = oldVideoUrl.split('/');
        const filenameWithExt = urlParts[urlParts.length - 1];
        const filename = filenameWithExt.split('.')[0];
        const publicId = `eshartak/${filename}`;
        
        await cloudinary.uploader.destroy(publicId, { resource_type: 'video' });
        console.log('Deleted old video from Cloudinary:', publicId);
      } catch (cloudErr) {
        console.log('Cloudinary delete error:', cloudErr);
      }
    }
    
    // Update sign with new video URL
    await db.collection('signs').doc(id).update({
      videoUrl: newVideoUrl,
      updatedAt: Date.now()
    });
    
    res.json({ 
      message: 'تم تحديث الفيديو بنجاح',
      videoUrl: newVideoUrl
    });
  } catch (err) {
    console.error('Error updating video:', err);
    res.status(500).json({ error: 'Failed to update video' });
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
    
    const videoUrl = signDoc.data().videoUrl;
    if (videoUrl && videoUrl.includes('cloudinary.com')) {
      try {
        const urlParts = videoUrl.split('/');
        const filenameWithExt = urlParts[urlParts.length - 1];
        const filename = filenameWithExt.split('.')[0];
        const publicId = `eshartak/${filename}`;
        
        await cloudinary.uploader.destroy(publicId, { resource_type: 'video' });
        console.log('Deleted from Cloudinary:', publicId);
      } catch (cloudErr) {
        console.log('Cloudinary delete error:', cloudErr);
      }
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
    
    const videoUrl = req.file.path;
    const submission = {
      destinationName,
      governorate,
      videoUrl,
      notes: notes || '',
      status: 'pending',
      createdAt: Date.now()
    };
    
    const docRef = await db.collection('submissions').add(submission);
    res.status(201).json({ message: 'تم استلام طلبك! سيتم المراجعة قريباً.' });
  } catch (err) {
    console.error(err);
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

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: Date.now() });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Eshartak server running on port ${PORT}`);
  console.log(`📁 Using Cloudinary for video storage`);
  console.log(`🔥 Using Firestore for database`);
});
