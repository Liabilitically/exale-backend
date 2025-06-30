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
const PORT = process.env.PORT || 8080;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

app.use(cors({
  origin: FRONTEND_URL,
  credentials: true,
}));
app.use(cookieParser());
app.use(express.json());

// Debug
app.post('/debug-body', (req, res) => {
  console.log('DEBUG BODY:', req.body);
  res.json({ received: req.body });
});

// Utils
function getOAuthClient(accessToken, refreshToken) {
  const oAuth2 = new google.auth.OAuth2(
    process.env.CLIENT_ID,
    process.env.CLIENT_SECRET,
    `${FRONTEND_URL}/oauth/callback`
  );
  oAuth2.setCredentials({ access_token: accessToken, refresh_token: refreshToken });
  return oAuth2;
}

function gmailClient(auth) {
  return google.gmail({ version: 'v1', auth });
}

// Auth
app.post('/authenticate', async (req, res) => {
  const code = req.body.code;
  if (!code) return res.status(400).json({ error: 'Missing code' });

  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: new URLSearchParams({
      code,
      client_id: process.env.CLIENT_ID,
      client_secret: process.env.CLIENT_SECRET,
      redirect_uri: `${FRONTEND_URL}/oauth/callback`,
      grant_type: 'authorization_code'
    })
  }).then(r => r.json());

  const { access_token, refresh_token } = tokenRes;
  if (!access_token || !refresh_token) {
    return res.status(400).json({ error: 'Token exchange failed' });
  }

  res
    .cookie('access_token', access_token, { httpOnly: true, secure: true, sameSite: FRONTEND_URL.startsWith('https') ? 'None' : 'Lax' })
    .cookie('refresh_token', refresh_token, { httpOnly: true, secure: true, sameSite: FRONTEND_URL.startsWith('https') ? 'None' : 'Lax' })
    .json({ message: 'Authenticated' });
});

app.get('/check-user', async (req, res) => {
  const { access_token, refresh_token } = req.cookies;
  if (!access_token || !refresh_token) return res.status(401).json({ error: 'Missing auth cookies' });

  const auth = getOAuthClient(access_token, refresh_token);
  const profile = await gmailClient(auth).users.getProfile({ userId:'me' });
  const email = profile.data.emailAddress;

  if (!await isUserAllowed(email)) return res.status(403).json({ error: 'User not authorized' });
  res.json({ status: 'ok', email });
});

// Add read-emails and draft endpoints similarly ensuring token refresh and await on DB functions…

app.listen(PORT, () => console.log(`Backend listening on port ${PORT}`));
