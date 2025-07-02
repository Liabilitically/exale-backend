// Fully updated backend `index.js` that works seamlessly with Vercel frontend
import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import fetch from 'node-fetch';
import base64url from 'base64url';
import { google } from 'googleapis';
import admin from 'firebase-admin';
import fs from 'fs';
const serviceAccount = JSON.parse(fs.readFileSync('./serviceAccountKey.json', 'utf8'));

// Firestore Setup
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();

// ENV Setup
dotenv.config();
const PORT = process.env.PORT || 8080;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
const GEMINI_API_KEY = process.env.GOOGLE_API_KEY;
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = `${FRONTEND_URL}/oauth/callback`;
const TOKEN_URI = 'https://oauth2.googleapis.com/token';
const NUMBER_OF_FETCHED_EMAILS = 10;

const COOKIE_OPTIONS = {
  httpOnly: true,
  sameSite: 'None',
  secure: true
};

const app = express();
app.use(cookieParser());
app.use(express.json());
app.use(cors({ origin: FRONTEND_URL, credentials: true }));

// ======= Firestore Helpers =======
async function isUserAllowed(email) {
  const doc = await db.collection('users').doc(email).get();
  return doc.exists;
}

async function getUserIndustry(email) {
  const doc = await db.collection('users').doc(email).get();
  return doc.exists ? doc.data().industry : '';
}

async function isMsgClassified(email, msgId) {
  const doc = await db.collection('users').doc(email).collection('classified_emails').doc(msgId).get();
  return doc.exists;
}

async function storeNewClassifiedMessage(data) {
  const ref = db.collection('users').doc(data.user_email).collection('classified_emails').doc(data.message_id);
  await ref.set({ ...data, drafted: false, timestamp: admin.firestore.FieldValue.serverTimestamp() });
}

async function setMessageToDrafted(email, msgId) {
  await db.collection('users').doc(email).collection('classified_emails').doc(msgId).update({ drafted: true });
}

async function getAllStoredLeads(email) {
  const snapshot = await db.collection('users').doc(email).collection('classified_emails').where('lead', '==', true).get();
  const results = {};
  snapshot.forEach(doc => (results[doc.id] = doc.data()));
  return results;
}

// ======= Gmail Helpers =======
function getGmailCreds(accessToken, refreshToken) {
  const auth = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
  auth.setCredentials({
    access_token: accessToken,
    refresh_token: refreshToken
  });
  return auth;
}

function buildGmailClient(auth) {
  return google.gmail({ version: 'v1', auth });
}

async function getUserEmail(auth) {
  const gmail = buildGmailClient(auth);
  const res = await gmail.users.getProfile({ userId: 'me' });
  return res.data.emailAddress;
}

async function getOrCreateLabel(service, labelName) {
  const existing = (await service.users.labels.list({ userId: 'me' })).data.labels?.find(l => l.name.toLowerCase() === labelName.toLowerCase());
  if (existing) return existing.id;
  const created = await service.users.labels.create({
    userId: 'me',
    requestBody: { name: labelName, labelListVisibility: 'labelShow', messageListVisibility: 'show' }
  });
  return created.data.id;
}

async function retryWithRefresh(requestFunc, refreshToken) {
  const tokenRes = await fetch(TOKEN_URI, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      refresh_token: refreshToken,
      grant_type: 'refresh_token'
    })
  }).then(res => res.json());
  const newToken = tokenRes.access_token;
  if (!newToken) throw new Error('Refresh failed');
  return [await requestFunc(getGmailCreds(newToken, refreshToken)), newToken];
}

// ========== Routes ==========
app.post('/authenticate', async (req, res) => {
  const code = req.body.code;
  const tokenRes = await fetch(TOKEN_URI, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uri: REDIRECT_URI,
      grant_type: 'authorization_code'
    })
  }).then(res => res.json());

  const { access_token, refresh_token } = tokenRes;
  if (!access_token || !refresh_token) return res.status(400).json({ detail: 'Missing token(s)' });

  res
  .cookie('access_token', access_token, COOKIE_OPTIONS)        // HttpOnly for security
  .cookie('refresh_token', refresh_token, COOKIE_OPTIONS)      // HttpOnly for security
  .json({ message: 'Authenticated' });

});

app.get('/check-user', async (req, res) => {
  const { access_token, refresh_token } = req.cookies;
  if (!access_token || !refresh_token)
    return res.status(401).json({ detail: 'Missing cookies' });

  let email;
  try {
    const creds = getGmailCreds(access_token, refresh_token);
    email = await getUserEmail(creds);
  } catch (err) {
    try {
      const [emailRes, newToken] = await retryWithRefresh(getUserEmail, refresh_token);
      email = emailRes;
      res.cookie('access_token', newToken, COOKIE_OPTIONS);
    } catch (refreshErr) {
      console.error('Token refresh failed:', refreshErr);
      return res.status(401).json({ detail: 'Token invalid' });
    }
  }

  const allowed = await isUserAllowed(email);
  if (!allowed) return res.status(403).json({ detail: 'User not registered' });

  return res.json({ status: 'ok' });
});

app.post('/read-emails', async (req, res) => {
  const { access_token, refresh_token } = req.cookies;
  if (!access_token || !refresh_token) return res.status(401).json({ detail: 'Missing cookies' });

  async function fetchEmails(creds) {
    const email = await getUserEmail(creds);
    const service = buildGmailClient(creds);
    const messages = (await service.users.messages.list({ userId: 'me', maxResults: NUMBER_OF_FETCHED_EMAILS })).data.messages || [];

    const filtered = [];
    for (const msg of messages) {
      if (!(await isMsgClassified(email, msg.id))) {
        const full = await service.users.messages.get({ userId: 'me', id: msg.id });
        const headers = full.data.payload?.headers || [];
        const subject = headers.find(h => h.name === 'Subject')?.value || '';
        const sender = headers.find(h => h.name === 'From')?.value || '';
        const snippet = full.data.snippet || '';
        if (!sender.includes(email)) {
          filtered.push({ id: msg.id, subject, sender, snippet });
        }
      }
    }
    return filtered;
  }

  let emails = [];
  let newToken = null;
  try {
    emails = await fetchEmails(getGmailCreds(access_token, refresh_token));
  } catch (err) {
    [emails, newToken] = await retryWithRefresh(fetchEmails, refresh_token);
    res.cookie('access_token', newToken, COOKIE_OPTIONS);
  }

  const userEmail = await getUserEmail(getGmailCreds(access_token, refresh_token));
  let newEmailsAvailable = false;
  if (emails.length > 0) {
    const prompt = `
      I have given below a list of emails from my inbox. Check if any of them are from potential leads for my ${await getUserIndustry(userEmail)} business.
      Your response should only be a single-line-CSV of indexes of emails that are from leads (indexes start at 0).
      Emails: ${JSON.stringify(emails)}
    `;
    const geminiRes = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-001:generateContent?key=${GEMINI_API_KEY}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] })
    });
    const result = (await geminiRes.json()).candidates?.[0]?.content?.parts?.[0]?.text?.trim() || '';
    const indexes = result.split(',').map(s => parseInt(s.trim())).filter(Number.isInteger);
    const leads = indexes.map(i => emails[i]);

    for (const email of emails) {
      await storeNewClassifiedMessage({ ...email, user_email: userEmail, message_id: email.id, lead: leads.includes(email) });
    }

    const service = buildGmailClient(getGmailCreds(access_token, refresh_token));
    const labelId = await getOrCreateLabel(service, 'Leads');
    for (const lead of leads) {
      await service.users.messages.modify({ userId: 'me', id: lead.id, requestBody: { addLabelIds: [labelId] } });
    }
    newEmailsAvailable = true;
  }

  const leads = await getAllStoredLeads(userEmail);
  leads.new_emails_available = newEmailsAvailable;
  res.json(leads);
});

app.post('/draft', async (req, res) => {
  const { access_token, refresh_token } = req.cookies;
  if (!access_token || !refresh_token) return res.status(401).json({ detail: 'Missing cookies' });
  const { email, msg_id } = req.body;
  if (!email || !msg_id) return res.status(400).json({ detail: 'Missing email data' });

  const prompt = `You're an AI assistant. Given this email from a lead, write a professional reply. ONLY include the body.\nEmail: "${email}"`;
  const replyData = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-001:generateContent?key=${GEMINI_API_KEY}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] })
  }).then(r => r.json());
  const reply = replyData.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || '';

  const creds = getGmailCreds(access_token, refresh_token);
  const userEmail = await getUserEmail(creds);
  const service = buildGmailClient(creds);
  const original = await service.users.messages.get({ userId: 'me', id: msg_id, format: 'metadata' });
  const headers = original.data.payload?.headers || [];
  const sender = headers.find(h => h.name.toLowerCase() === 'from')?.value || '';
  const subject = headers.find(h => h.name.toLowerCase() === 'subject')?.value || 'Re: Lead';
  const threadId = original.data.threadId;

  const raw = base64url.encode(`To: ${sender}\nSubject: Re: ${subject}\nIn-Reply-To: ${msg_id}\nReferences: ${msg_id}\n\n${reply}`);
  await service.users.drafts.create({ userId: 'me', requestBody: { message: { raw, threadId } } });
  await setMessageToDrafted(userEmail, msg_id);
  res.send(reply);
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
