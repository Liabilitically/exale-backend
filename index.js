const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const axios = require("axios");
const { google } = require("googleapis");
const { GoogleGenerativeAI } = require("@google/generative-ai");
require("dotenv").config();

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(cookieParser());
app.use(express.json());

const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;
const TOKEN_URI = "https://oauth2.googleapis.com/token";
const NUMBER_OF_FETCHED_EMAILS = 10;
const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);

function getGmailClient(access_token) {
  return google.gmail({ version: "v1", auth: access_token });
}

async function getUserEmail(auth) {
  const gmail = getGmailClient(auth);
  const profile = await gmail.users.getProfile({ userId: "me" });
  return profile.data.emailAddress;
}

app.post("/authenticate", async (req, res) => {
  const { code } = req.body;
  const tokenRes = await axios.post(TOKEN_URI, {
    code,
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    redirect_uri: REDIRECT_URI,
    grant_type: "authorization_code",
  });
  res.cookie("access_token", tokenRes.data.access_token, { httpOnly: true });
  res.cookie("refresh_token", tokenRes.data.refresh_token, { httpOnly: true });
  res.json({ message: "Authenticated" });
});

app.post("/read-emails", async (req, res) => {
  try {
    const access_token = req.cookies.access_token;
    const gmail = getGmailClient(access_token);
    const selfEmail = await getUserEmail(access_token);

    const listRes = await gmail.users.messages.list({ userId: "me", maxResults: NUMBER_OF_FETCHED_EMAILS });
    const messages = listRes.data.messages || [];
    const emails = [];

    for (const msg of messages) {
      const detail = await gmail.users.messages.get({ userId: "me", id: msg.id });
      const headers = detail.data.payload.headers;
      const subject = headers.find(h => h.name === "Subject")?.value || "";
      const sender = headers.find(h => h.name === "From")?.value || "";
      const snippet = detail.data.snippet || "";

      if (!sender.includes(selfEmail)) {
        emails.push({ id: msg.id, subject, sender, snippet });
      }
    }

    const prompt = `I have given below a list of emails from my inbox. Check if any of them are from potential leads for my business. Your response should only be a single-line-CSV of indexes of emails that are from leads (indexes start at 0). Emails: ${JSON.stringify(emails)}`;
    const result = await genAI.getGenerativeModel({ model: "gemini-pro" }).generateContent(prompt);
    const text = await result.response.text();
    const indexes = text.match(/\d+/g)?.map(Number) || [];
    const leads = indexes.map(i => emails[i]);

    res.json({ leads, new_emails_available: emails.length > 0 });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to fetch emails" });
  }
});

app.listen(8080, () => console.log("Server running on port 8080"));