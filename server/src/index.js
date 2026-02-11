require('dotenv').config();
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const { VerusIdInterface, primitives } = require('verusid-ts-client');
const { randomBytes } = require('crypto');

const { PRIVATE_KEY, SIGNING_IADDRESS, CHAIN, API, CHAIN_IADDRESS, SERVER_URL } = process.env;
const VerusId = new VerusIdInterface(CHAIN, API);

const I_ADDRESS_VERSION = 102;
const port = process.env.LOGIN_PORT || 8000;

// Store challenges in memory (platform DB handles persistence)
const challenges = new Map();

function generateChallengeID(len = 20) {
  const buf = randomBytes(len);
  return primitives.toBase58Check(Buffer.from(buf), I_ADDRESS_VERSION);
}

const app = express();
app.use(bodyParser.json({ limit: '1mb' }));
app.use(cors({ origin: '*' }));

// Log ALL incoming requests for debugging
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} from ${req.ip}`);
  next();
});

// Health/debug endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});

// Generate a login challenge
app.post('/login', async (req, res) => {
  try {
    const challenge_id = generateChallengeID();

    const request = await VerusId.createLoginConsentRequest(
      SIGNING_IADDRESS,
      new primitives.LoginConsentChallenge({
        challenge_id: challenge_id,
        requested_access: [
          new primitives.RequestedPermission(primitives.IDENTITY_VIEW.vdxfid)
        ],
        redirect_uris: [
          new primitives.RedirectUri(
            `https://login.autobb.app/verusidlogin`,
            primitives.LOGIN_CONSENT_WEBHOOK_VDXF_KEY.vdxfid
          ),
        ],
        subject: [],
        provisioning_info: [],
        created_at: Number((Date.now() / 1000).toFixed(0)),
      }),
      PRIVATE_KEY,
      null,
      null,
      CHAIN_IADDRESS
    );

    // Self-verify the request before sending
    const verified = await VerusId.verifyLoginConsentRequest(
      primitives.LoginConsentRequest.fromWalletDeeplinkUri(request.toWalletDeeplinkUri()),
      null,
      CHAIN_IADDRESS
    );
    console.log("Login Request Signed Correctly:", verified, challenge_id);

    if (!verified) {
      return res.status(500).json({ error: 'Failed to self-verify login request' });
    }

    const deeplink = request.toWalletDeeplinkUri();
    
    // Store challenge
    challenges.set(challenge_id, { status: 'pending', createdAt: Date.now() });

    // Generate QR as data URL
    const QRCode = require('qrcode');
    const qrDataUrl = await QRCode.toDataURL(deeplink, {
      width: 300,
      margin: 2,
      color: { dark: '#000000', light: '#ffffff' },
    });

    res.json({
      data: {
        challengeId: challenge_id,
        deeplink,
        qrDataUrl,
        expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
      }
    });
  } catch (e) {
    console.error("Login challenge error:", e);
    res.status(500).json({ error: e.message || 'Failed to create login challenge' });
  }
});

// Callback from Verus Mobile
app.post('/verusidlogin', async (req, res) => {
  try {
    const data = req.body;
    console.log("Received login callback, keys:", Object.keys(data || {}));
    console.log("Body preview:", JSON.stringify(data).substring(0, 500));
    
    let loginResponse = new primitives.LoginConsentResponse(data);
    console.log("LoginConsentResponse created, signing_id:", loginResponse.signing_id);
    
    let verified = false;
    try {
      verified = await VerusId.verifyLoginConsentResponse(loginResponse);
    } catch (verifyErr) {
      console.error("Verification error:", verifyErr.message);
    }
    console.log("Login signature verified:", verified);

    if (!verified) {
      return res.status(400).json({ error: 'Signature verification failed' });
    }

    const challengeId = loginResponse.decision.request.challenge.challenge_id;
    const signingId = loginResponse.signing_id;

    // Forward to platform API to create session (use internal URL, not public)
    const PLATFORM_INTERNAL_URL = process.env.PLATFORM_INTERNAL_URL || 'http://localhost:3000';
    try {
      const platformRes = await fetch(`${PLATFORM_INTERNAL_URL}/auth/qr/callback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          challengeId,
          signingId,
          verified: true,
        }),
      });
      console.log("Platform callback status:", platformRes.status);
    } catch (e) {
      console.error("Platform callback failed:", e.message);
    }

    res.send(true);
  } catch (e) {
    console.error("Login verification error:", e);
    res.status(400).json({ error: e.message || 'Verification failed' });
  }
});

// Status check (for platform to poll)
app.get('/status/:challengeId', (req, res) => {
  const challenge = challenges.get(req.params.challengeId);
  if (!challenge) return res.status(404).json({ error: 'Not found' });
  res.json({ data: challenge });
});

app.listen(port, () => {
  console.log(`VerusID Login server running on port ${port}`);
});
