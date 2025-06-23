import { initializeApp, applicationDefault } from 'firebase-admin/app';
import { getFirestore, FieldValue } from 'firebase-admin/firestore';
import dotenv from 'dotenv';

dotenv.config();

// Initialize Firestore Admin SDK
initializeApp({
  credential: applicationDefault()
});

const db = getFirestore();

// ✅ Check if user is allowed
export async function isUserAllowed(userEmail) {
  const docRef = db.collection('users').doc(userEmail);
  const doc = await docRef.get();
  return doc.exists;
}

// ✅ Check if message already classified
export async function isMsgClassified(userEmail, messageId) {
  const docRef = db.collection('users').doc(userEmail).collection('classified_emails').doc(messageId);
  const doc = await docRef.get();
  return doc.exists;
}

// ✅ Store classified email message
export async function storeNewClassifiedMessage({ user_email, message_id, lead, subject, sender, snippet }) {
  const docRef = db
    .collection('users')
    .doc(user_email)
    .collection('classified_emails')
    .doc(message_id);

  await docRef.set({
    lead,
    drafted: false,
    subject,
    sender,
    snippet,
    timestamp: FieldValue.serverTimestamp()
  });
}

// ✅ Get all stored leads for user
export async function getAllStoredLeads(userEmail) {
  const querySnapshot = await db
    .collection('users')
    .doc(userEmail)
    .collection('classified_emails')
    .where('lead', '==', true)
    .get();

  const storedLeads = {};
  querySnapshot.forEach(doc => {
    storedLeads[doc.id] = doc.data();
  });

  return storedLeads;
}

// ✅ Get industry for a user
export async function getUserIndustry(userEmail) {
  const doc = await db.collection('users').doc(userEmail).get();
  return doc.data().industry;
}

// ✅ Set message to drafted
export async function setMessageToDrafted(userEmail, messageId) {
  const docRef = db
    .collection('users')
    .doc(userEmail)
    .collection('classified_emails')
    .doc(messageId);

  await docRef.update({
    drafted: true
  });
}