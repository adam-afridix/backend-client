const express = require("express");
const cors = require("cors");
const multer = require("multer");
const { google } = require("googleapis");
const dotenv = require("dotenv");
const stream = require("stream");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// CORS Configuration - ONLY ONCE
app.use(cors({
  origin: [
    'http://localhost:3000',
    'http://localhost:5173',
    'https://aquamarine-semolina-dd6e68.netlify.app'
  ],
  credentials: true
}));

// Middleware
app.use(express.json());

// Configure multer for file uploads (store in memory)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 100 * 1024 * 1024, // 100MB
  },
});

// ============================================
// 🔐 AUTHENTICATION MIDDLEWARE
// ============================================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access denied. Please login.' });
  }

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (error) {
    res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// ============================================
// 🔑 LOGIN ROUTE
// ============================================
app.post("/api/auth/login", async (req, res) => {
  const { username, password, rememberMe } = req.body;

  try {
    // Check username
    if (username !== process.env.ADMIN_USERNAME) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Check password (plain text comparison for simplicity)
    // For production, use bcrypt.compare() with hashed passwords
    if (password !== process.env.ADMIN_PASSWORD) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Create token
    const expiresIn = rememberMe ? '30d' : '24h';
    const token = jwt.sign(
      { username: username },
      process.env.JWT_SECRET,
      { expiresIn: expiresIn }
    );

    console.log(`✅ User "${username}" logged in successfully`);

    res.json({ 
      success: true,
      token: token,
      message: 'Login successful' 
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// ============================================
// 🔓 VERIFY TOKEN ROUTE
// ============================================
app.get("/api/auth/verify", authenticateToken, (req, res) => {
  res.json({ valid: true, user: req.user });
});

// OAuth2 configuration
const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.REACT_APP_API_URL
);

// Token file path
const TOKEN_PATH = path.join(__dirname, "google-token.json");

// Load saved token
if (fs.existsSync(TOKEN_PATH)) {
  const token = JSON.parse(fs.readFileSync(TOKEN_PATH));
  oauth2Client.setCredentials(token);
  console.log("✅ OAuth token loaded from file");
}

// Save token
function saveToken(token) {
  fs.writeFileSync(TOKEN_PATH, JSON.stringify(token));
  console.log("✅ Token saved to file");
}

const drive = google.drive({ version: "v3", auth: oauth2Client });

// UPLOAD FILE TO GOOGLE DRIVE
async function uploadFileToGoogleDrive(file) {
  const fileMetadata = {
    name: file.originalname,
    parents: [process.env.GOOGLE_DRIVE_FOLDER_ID],
  };

  const media = {
    mimeType: file.mimetype,
    body: stream.Readable.from(file.buffer),
  };

  try {
    const response = await drive.files.create({
      requestBody: fileMetadata,
      media: media,
      fields: "id, name, webViewLink, webContentLink",
      supportsAllDrives: true,
    });

    return response.data;
  } catch (error) {
    console.error("Error uploading to Google Drive:", error);
    throw error;
  }
}

// Health check
app.get("/", (req, res) => {
  res.json({
    message: "Backend server is running!",
    status: "OK",
    authenticated: !!oauth2Client.credentials.access_token,
  });
});

// Step 1: Get OAuth URL (🔒 PROTECTED)
app.get("/api/auth/url", authenticateToken, (req, res) => {
  const authUrl = oauth2Client.generateAuthUrl({
    access_type: "offline",
    scope: ["https://www.googleapis.com/auth/drive.file"],
    prompt: "consent",
  });
  res.json({ authUrl });
});

// Step 2: OAuth Callback
app.get("/api/auth/callback", async (req, res) => {
  const { code } = req.query;

  if (!code) {
    return res.status(400).send("No authorization code provided");
  }

  try {
    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);
    saveToken(tokens);

    res.send(`
      <html>
        <body style="font-family: Arial; text-align: center; padding: 50px;">
          <h1 style="color: #22c55e;">✅ Authentication Successful!</h1>
          <p>You can close this window and return to your app.</p>
        </body>
      </html>
    `);
  } catch (error) {
    console.error("Error getting tokens:", error);
    res.status(500).send("Authentication failed");
  }
});

// Auth status (🔒 PROTECTED)
app.get("/api/auth/status", authenticateToken, (req, res) => {
  const authenticated = !!oauth2Client.credentials.access_token;
  res.json({
    authenticated,
    expiresAt: oauth2Client.credentials.expiry_date,
  });
});

// ============================================
// UPLOAD FILES WITH METADATA (🔒 PROTECTED)
// ============================================
app.post(
  "/api/upload",
  authenticateToken, // 👈 Added authentication
  upload.fields([
    { name: "files", maxCount: 50 },
    { name: "metadata", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      if (!oauth2Client.credentials.access_token) {
        return res.status(401).json({
          error: "Not authenticated",
          message: "Authenticate with Google first",
        });
      }

      const files = req.files["files"] || [];
      const metadataFile = req.files["metadata"] ? req.files["metadata"][0] : null;

      if (files.length === 0) {
        return res.status(400).json({ error: "No files uploaded" });
      }

      console.log(`📤 Uploading ${files.length} file(s)...`);
      
      const uploadedFiles = [];

      // Upload metadata file FIRST if it exists
      if (metadataFile) {
        console.log("📝 Uploading metadata file:", metadataFile.originalname);
        
        const metadataFileMetadata = {
          name: metadataFile.originalname,
          parents: [process.env.GOOGLE_DRIVE_FOLDER_ID],
        };

        const metadataMedia = {
          mimeType: "application/json",
          body: stream.Readable.from(metadataFile.buffer),
        };

        const metadataResponse = await drive.files.create({
          requestBody: metadataFileMetadata,
          media: metadataMedia,
          fields: "id, name, webViewLink, webContentLink",
          supportsAllDrives: true,
        });

        uploadedFiles.push({
          name: metadataFile.originalname,
          id: metadataResponse.data.id,
          webViewLink: metadataResponse.data.webViewLink,
          webContentLink: metadataResponse.data.webContentLink,
          type: "metadata",
        });

        console.log("✅ Metadata file uploaded:", metadataResponse.data.name);
      }

      // Upload all other files
      const fileUploadPromises = files.map((file) =>
        uploadFileToGoogleDrive(file)
      );

      const fileResults = await Promise.all(fileUploadPromises);
      
      fileResults.forEach(result => {
        uploadedFiles.push({
          ...result,
          type: "file"
        });
      });

      console.log(`✅ Successfully uploaded ${uploadedFiles.length} file(s) to Google Drive`);

      res.json({
        message: "Files uploaded successfully",
        files: uploadedFiles,
        count: uploadedFiles.length,
      });
    } catch (error) {
      console.error("❌ Upload error:", error);
      res.status(500).json({
        error: "Failed to upload files",
        details: error.message,
      });
    }
  }
);

// LIST FILES (🔒 PROTECTED)
app.get("/api/files", authenticateToken, async (req, res) => {
  try {
    if (!oauth2Client.credentials.access_token) {
      return res.status(401).json({
        error: "Not authenticated",
        message: "Authenticate first",
      });
    }

    const response = await drive.files.list({
      q: `'${process.env.GOOGLE_DRIVE_FOLDER_ID}' in parents and trashed=false`,
      fields: "files(id, name, mimeType, createdTime, webViewLink)",
      orderBy: "createdTime desc",
      supportsAllDrives: true,
      includeItemsFromAllDrives: true,
    });

    res.json({
      files: response.data.files,
      count: response.data.files.length,
    });
  } catch (error) {
    console.error("Error fetching files:", error);
    res.status(500).json({
      error: "Failed to fetch files",
      details: error.message,
    });
  }
});

// ============================================
// n8n WEBHOOK ROUTES (🔒 PROTECTED)
// ============================================

// Route to send YouTube link to n8n (🔒 PROTECTED)
app.post("/api/n8n/youtube-link", authenticateToken, async (req, res) => {
  try {
    const { url } = req.body;

    if (!url) {
      return res.status(400).json({ error: "No URL provided" });
    }

    if (!url.includes("youtube.com") && !url.includes("youtu.be")) {
      return res.status(400).json({ error: "Invalid YouTube URL" });
    }

    console.log("Sending to n8n:", url);

    const response = await fetch(process.env.N8N_YOUTUBE_LINK_WEBHOOK, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        type: "youtube",
        url: url,
        timestamp: new Date().toISOString(),
      }),
    });

    console.log("n8n response status:", response.status);

    if (!response.ok) {
      throw new Error(`n8n webhook failed: ${response.status}`);
    }

    const responseText = await response.text();
    console.log("n8n raw response:", responseText);

    let result;
    try {
      result = JSON.parse(responseText);
    } catch (parseError) {
      console.warn("n8n returned non-JSON response:", responseText);
      return res.json({
        success: true,
        message: "YouTube link sent to n8n successfully",
        n8nResponse: {
          raw: responseText,
          note: "n8n webhook accepted the data (non-JSON response)",
        },
      });
    }

    if (Array.isArray(result)) {
      result = result[0];
    }

    res.json({
      success: true,
      message: "YouTube link sent to n8n successfully",
      n8nResponse: result,
    });
  } catch (error) {
    console.error("Error sending to n8n:", error);
    res.status(500).json({
      success: false,
      error: "Failed to send to n8n",
      details: error.message,
    });
  }
});

// Paste text route (🔒 PROTECTED)
app.post("/api/n8n/paste-text", authenticateToken, async (req, res) => {
  try {
    const { content, metadata } = req.body;

    if (!content) {
      return res.status(400).json({ error: "No content provided" });
    }

    console.log("Sending text to n8n, length:", content.length);
    console.log("Metadata received:", metadata);

    // Build the payload with all data
    const payload = {
      type: "text",
      content: content,
      wordCount: content.split(/\s+/).filter((word) => word.length > 0).length,
      characterCount: content.length,
      timestamp: new Date().toISOString(),
    };

    // Add metadata if provided
    if (metadata) {
      payload.metadata = {
        title: metadata.title || "",
        description: metadata.description || "",
        category: metadata.category || "",
        publishedDate: metadata.publishedDate || "",
        tags: Array.isArray(metadata.tags) ? metadata.tags : [],
      };
    }

    console.log("Full payload to n8n:", JSON.stringify(payload, null, 2));

    const response = await fetch(process.env.N8N_PASTE_TEXT_WEBHOOK, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    console.log("n8n response status:", response.status);

    if (!response.ok) {
      throw new Error(`n8n webhook failed: ${response.status}`);
    }

    const responseText = await response.text();
    console.log("n8n raw response:", responseText);

    let result;
    try {
      result = JSON.parse(responseText);
    } catch (parseError) {
      console.warn("n8n returned non-JSON response:", responseText);
      return res.json({
        success: true,
        message: "Text and metadata sent to n8n successfully",
        n8nResponse: {
          raw: responseText,
          note: "n8n webhook accepted the data (non-JSON response)",
        },
      });
    }

    if (Array.isArray(result)) {
      result = result[0];
    }

    res.json({
      success: true,
      message: "Text and metadata sent to n8n successfully",
      n8nResponse: result,
    });
  } catch (error) {
    console.error("Error sending to n8n:", error);
    res.status(500).json({
      success: false,
      error: "Failed to send to n8n",
      details: error.message,
    });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`✅ Backend server running on http://localhost:${PORT}`);
  console.log(`📁 Google Drive Folder ID: ${process.env.GOOGLE_DRIVE_FOLDER_ID}`);
  console.log(`🔗 n8n Paste Text Webhook: ${process.env.N8N_PASTE_TEXT_WEBHOOK}`);
  console.log(`🔗 n8n YouTube Link Webhook: ${process.env.N8N_YOUTUBE_LINK_WEBHOOK}`);
  console.log(`🔐 Login Username: ${process.env.ADMIN_USERNAME}`);

  if (oauth2Client.credentials.access_token) {
    console.log("🔐 Authenticated with Google Drive");
  } else {
    console.log(`⚠️ Not authenticated - open http://localhost:${PORT}/api/auth/url`);
  }

  console.log("🚀 Ready for file uploads and n8n webhooks!");
});