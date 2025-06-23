import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import fetch from 'node-fetch';
import base64url from 'base64url';
import { google } from 'googleapis';
import {
  isUserAllowed,
  isMsgClassified,
  storeNewClassifiedMessage,
  setMessageToDrafted,
  getAllStoredLeads,
  getUserIndustry
} from './firestoreDatabase.js';

dotenv.config();

const app = express();
app.use(cookieParser());
app.use(express.json());

app.use(cors({
  origin: FRONTEND_URL,
  credentials: true,
}));

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
  secure: true,
};

// =============== Utils ===============

function getGmailCreds(accessToken, refreshToken) {
  return new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI).setCredentials({
    access_token: accessToken,
    refresh_token: refreshToken
  });
}

function buildGmailClient(auth) {
  return google.gmail({ version: 'v1', auth: auth });
}

async function getOrCreateLabel(service, labelName) {
  const res = await service.users.labels.list({ userId: 'me' });
  const labels = res.data.labels || [];

  const existing = labels.find(l => l.name.toLowerCase() === labelName.toLowerCase());
  if (existing) return existing.id;

  const newLabel = await service.users.labels.create({
    userId: 'me',
    requestBody: {
      name: labelName,
      labelListVisibility: 'labelShow',
      messageListVisibility: 'show'
    }
  });
  return newLabel.data.id;
}

async function retryWithRefresh(requestFunc, refreshToken) {
  const res = await fetch(TOKEN_URI, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      refresh_token: refreshToken,
      grant_type: 'refresh_token'
    })
  });
  const tokenRes = await res.json();
  const newToken = tokenRes.access_token;
  if (!newToken) throw new Error('Failed to refresh token');
  const creds = getGmailCreds(newToken, refreshToken);
  return [await requestFunc(creds), newToken];
}

async function getUserEmail(auth) {
  const service = buildGmailClient(auth);
  const profile = await service.users.getProfile({ userId: 'me' });
  return profile.data.emailAddress;
}

// =============== AUTH =================

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

  if (!access_token || !refresh_token) {
    return res.status(400).json({ detail: 'Missing token(s)' });
  }

  res
    .cookie('access_token', access_token, COOKIE_OPTIONS)
    .cookie('refresh_token', refresh_token, COOKIE_OPTIONS)
    .json({ message: 'Authenticated' });
});

app.post('/logout', (req, res) => {
  res
    .clearCookie('access_token')
    .clearCookie('refresh_token')
    .json({ message: 'Logged out' });
});

app.post('/refresh-token', async (req, res) => {
  const refreshToken = req.cookies.refresh_token;
  if (!refreshToken) return res.status(401).json({ detail: 'No refresh token' });

  const tokenRes = await fetch(TOKEN_URI, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      refresh_token: refreshToken,
      grant_type: 'refresh_token'
    })
  }).then(r => r.json());

  const newToken = tokenRes.access_token;
  if (!newToken) return res.status(401).json({ detail: 'Refresh failed' });

  res
    .cookie('access_token', newToken, COOKIE_OPTIONS)
    .json({ message: 'Token refreshed' });
});

app.get('/check-user', async (req, res) => {
  const { access_token, refresh_token } = req.cookies;
  if (!access_token || !refresh_token) return res.status(401).json({ detail: 'Missing cookies' });

  const creds = getGmailCreds(access_token, refresh_token);
  const email = await getUserEmail(creds);

  if (!isUserAllowed(email)) return res.status(403).json({ detail: 'User not registered' });

  return res.json({ status: 'ok' });
});

// =============== READ EMAILS =================

app.post('/read-emails', async (req, res) => {
  const { access_token, refresh_token } = req.cookies;
  if (!access_token || !refresh_token) return res.status(401).json({ detail: 'Missing cookies' });

  async function fetchEmails(creds) {
    const userEmail = await getUserEmail(creds);
    const service = buildGmailClient(creds);
    const rawMsgs = await service.users.messages.list({
      userId: 'me',
      maxResults: NUMBER_OF_FETCHED_EMAILS
    }).then(r => r.data.messages || []);

    const emails = [];
    for (const msg of rawMsgs) {
      if (!isMsgClassified(userEmail, msg.id)){
        const detail = await service.users.messages.get({ userId: 'me', id: msg.id });
        const headers = detail.data.payload?.headers || [];
        const subject = headers.find(h => h.name === 'Subject')?.value || '';
        const sender = headers.find(h => h.name === 'From')?.value || '';
        const snippet = detail.data.snippet || '';

        if (!sender.includes(userEmail)) {
          emails.push({ id: msg.id, subject, sender, snippet });
        }
      }
    }
    return emails;
  }

  let emails = [];
  let newToken = null;
  try {
    const creds = getGmailCreds(access_token, refresh_token);
    emails = await fetchEmails(creds);
  } catch (err) {
    [emails, newToken] = await retryWithRefresh(fetchEmails, refresh_token);
    res.cookie('access_token', newToken, COOKIE_OPTIONS);
  }

  const userEmail = await getUserEmail(getGmailCreds(access_token, refresh_token));
  let newEmailsAvailable = false;

  if (emails.length > 0) {
    const prompt = `
    I have given below a list of emails from my inbox. Check if any of them are from potential leads for my ${getUserIndustry(userEmail)} business.
    Your response should only be a single-line-CSV of indexes of emails that are from leads (indexes start at 0).
    Emails:
    ${JSON.stringify(emails)}
    `;
    const geminiRes = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-001:generateContent?key=${GEMINI_API_KEY}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] })
    });
    const geminiData = await geminiRes.json();
    const resultText = geminiData.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || '';
    const indexes = resultText.split(',').map(s => parseInt(s.trim())).filter(Number.isInteger);
    const leads = indexes.map(i => emails[i]);

    for (const email of emails) {
      storeNewClassifiedMessage({
        user_email: userEmail,
        message_id: email.id,
        lead: leads.includes(email),
        subject: email.subject,
        sender: email.sender,
        snippet: email.snippet
      });
    }

    const service = buildGmailClient(getGmailCreds(access_token, refresh_token));
    const labelId = await getOrCreateLabel(service, 'Leads');
    for (const lead of leads) {
      await service.users.messages.modify({
        userId: 'me',
        id: lead.id,
        requestBody: { addLabelIds: [labelId] }
      });
    }

    newEmailsAvailable = true;
  }

  const leads = getAllStoredLeads(userEmail);
  leads.new_emails_available = newEmailsAvailable;
  res.json(leads);
});

// =============== DRAFT =================

app.post('/draft', async (req, res) => {
  const { access_token, refresh_token } = req.cookies;
  if (!access_token || !refresh_token) return res.status(401).json({ detail: 'Missing cookies' });

  const { email, msg_id } = req.body;
  if (!email || !msg_id) return res.status(400).json({ detail: 'Missing email data' });

  const prompt = `You're an AI assistant. Given this email from a lead, write a professional reply. ONLY include the body.\nEmail: "${email}"`;

  const replyRes = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-001:generateContent?key=${GEMINI_API_KEY}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] })
  });
  const replyData = await replyRes.json();
  const reply = replyData.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || '';

  try {
    const creds = getGmailCreds(access_token, refresh_token);
    const userEmail = await getUserEmail(creds);
    const service = buildGmailClient(creds);

    const original = await service.users.messages.get({ userId: 'me', id: msg_id, format: 'metadata' });
    const headers = original.data.payload?.headers || [];
    const sender = headers.find(h => h.name.toLowerCase() === 'from')?.value || '';
    const subject = headers.find(h => h.name.toLowerCase() === 'subject')?.value || 'Re: Lead';
    const threadId = original.data.threadId;

    const messageText = `To: ${sender}\nSubject: Re: ${subject}\nIn-Reply-To: ${msg_id}\nReferences: ${msg_id}\n\n${reply}`;
    const raw = base64url.encode(messageText);

    await service.users.drafts.create({
      userId: 'me',
      requestBody: {
        message: {
          raw,
          threadId
        }
      }
    });

    setMessageToDrafted(userEmail, msg_id);
    res.send(reply);

  } catch (err) {
    console.error('Draft creation failed:', err);
    res.status(500).json({ detail: 'Draft creation failed' });
  }
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
