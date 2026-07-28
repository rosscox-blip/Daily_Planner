// netlify/functions/jobs.js
// Returns the authenticated team member's job data.
// Netlify automatically verifies the Identity JWT and injects context.clientContext.user.
const fs   = require('fs');
const path = require('path');

const ADMIN_EMAIL = 'ross.cox@arrive.com';

const EMAIL_MAP = {
  'emievic.yousaf@arrive.com':       'emie',
  'jayprakash.basaliyal@arrive.com': 'jay',
  'robert.smith@arrive.com':         'rob',
  'ross.cox@arrive.com':             'ross',
  'sofia.bater@arrive.com':          'sofia',
  'suna.olgac@arrive.com':           'suna',
  'tristan.pointer@arrive.com':      'tristan',
  'joe.stanton@arrive.com':          'joe',
  'anna.kulesza@arrive.com':         'anna',
};

exports.handler = async (event, context) => {
  const { user } = context.clientContext || {};

  if (!user) {
    return { statusCode: 401, body: JSON.stringify({ error: 'Not authenticated' }) };
  }

  const userEmail = user.email.toLowerCase();
  let member;

  if (userEmail === ADMIN_EMAIL) {
    // Admin can view any member's page — page passes ?member= in the request
    member = (event.queryStringParameters || {}).member || '';
    if (!member) {
      return { statusCode: 400, body: JSON.stringify({ error: 'member param required' }) };
    }
  } else {
    member = EMAIL_MAP[userEmail];
    if (!member) {
      return { statusCode: 403, body: JSON.stringify({ error: 'Not authorised' }) };
    }
  }

  const dataPath = path.join(__dirname, 'data', member + '.json');
  try {
    const data = fs.readFileSync(dataPath, 'utf8');
    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: data,
    };
  } catch (e) {
    return { statusCode: 404, body: JSON.stringify({ error: 'Data file not found' }) };
  }
};
