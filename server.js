import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import QRCode from 'qrcode';
import { v4 as uuidv4 } from 'uuid';
import jwt from 'jsonwebtoken';
import { GoogleAuth } from 'google-auth-library';
import fs from 'fs';
// Debug: verifica se i certificati esistono
try {
  console.log("🔍 Verifica certificati su Render...");
  console.log("/etc/secrets/pass.p12 →", fs.existsSync("/etc/secrets/pass.p12"));
  console.log("/etc/secrets/wwdr.cer →", fs.existsSync("/etc/secrets/wwdr.cer"));
  console.log("./certs/pass.p12 →", fs.existsSync("./certs/pass.p12"));
  console.log("./certs/wwdr.cer →", fs.existsSync("./certs/wwdr.cer"));
} catch (e) {
  console.error("Errore controllo certificati:", e);
}

import { PKPass } from 'passkit-generator';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// --- Apple Wallet config ---
const APPLE = {
  passTypeIdentifier: process.env.APPLE_PASS_TYPE_IDENTIFIER,
  teamIdentifier: process.env.APPLE_TEAM_IDENTIFIER,
  certPath: process.env.APPLE_CERT_PATH || '/etc/secrets/signerCert.pem',
  keyPath: process.env.APPLE_KEY_PATH || '/etc/secrets/signerKey.pem',
   wwdrPath: process.env.APPLE_WWDR_PATH || '/etc/secrets/wwdr.cer'
};

// --- Google Wallet config ---
let GOOGLE = {
  issuerId: process.env.GOOGLE_ISSUER_ID,
  classSuffix: process.env.GOOGLE_CLASS_SUFFIX || 'businesscard',
  saEmail: '',
  saPrivateKey: ''
};

// Leggi credenziali Google da Secret File
const googleSaPath = '/etc/secrets/google-sa-key.json';
if (fs.existsSync(googleSaPath)) {
  try {
    const saFile = JSON.parse(fs.readFileSync(googleSaPath, 'utf8'));
    GOOGLE.saEmail = saFile.client_email;
    GOOGLE.saPrivateKey = saFile.private_key;
    console.log('✅ Credenziali Google caricate da Secret File');
  } catch (e) {
    console.error('❌ Errore lettura google-sa-key.json:', e);
  }
} else {
  // Fallback alle variabili d'ambiente
  GOOGLE.saEmail = process.env.GOOGLE_SA_EMAIL;
  GOOGLE.saPrivateKey = (process.env.GOOGLE_SA_PRIVATE_KEY || '').replace(/\\n/g, '\n');
  console.log('⚠️ Google SA key da variabili d\'ambiente (considera di usare Secret File)');
}

// Simple validation check
function assertEnv() {
  const missing = [];
  if (!APPLE.passTypeIdentifier) missing.push('APPLE_PASS_TYPE_IDENTIFIER');
  if (!APPLE.teamIdentifier) missing.push('APPLE_TEAM_IDENTIFIER');
  if (!APPLE.certPath || !fs.existsSync(APPLE.certPath)) missing.push('APPLE_CERT_PATH (file mancante)');
  if (!APPLE.keyPath || !fs.existsSync(APPLE.keyPath)) missing.push('APPLE_KEY_PATH (file mancante)');
  if (!APPLE.wwdrPath || !fs.existsSync(APPLE.wwdrPath)) console.warn('[WARN] APPLE_WWDR_PATH non trovato');
  if (!GOOGLE.issuerId) missing.push('GOOGLE_ISSUER_ID');
  if (!GOOGLE.saEmail) missing.push('GOOGLE_SA_EMAIL');
  if (!GOOGLE.saPrivateKey) missing.push('GOOGLE_SA_PRIVATE_KEY');
  if (missing.length) {
    console.error('Variabili mancanti:', missing.join(', '));
  }
}
assertEnv();

// Ensure folders
const passesDir = path.join(__dirname, 'passes');
if (!fs.existsSync(passesDir)) fs.mkdirSync(passesDir);

// Minimal assets (PNG files) for the pass
const assetsDir = path.join(__dirname, 'assets');

// Utility: ensure Google Generic Class exists (best-effort)
async function ensureGoogleGenericClass(authClient, classId) {
  const url = `https://walletobjects.googleapis.com/walletobjects/v1/genericClass/${encodeURIComponent(classId)}`;
  const headers = { Authorization: `Bearer ${await authClient.getAccessToken()}`, 'Content-Type': 'application/json' };

  // Try to GET class
  let res = await fetch(url, { headers });
  if (res.status === 200) return true;

  if (res.status === 404) {
    // Create it
    const body = {
      id: classId,
      classTemplateInfo: {
        cardTemplateOverride: {
          cardRowTemplateInfos: [
            { twoItems: { startItem: { firstValue: { fields: [{fieldPath:'object.textModulesData[0]'}] } },
                          endItem:   { firstValue: { fields: [{fieldPath:'object.textModulesData[1]'}] } } } }
          ]
        }
      },
      reviewStatus: "UNDER_REVIEW",  // or "DRAFT" initially
      title: "Business Card",
      issuerName: "Your Brand",
      hexBackgroundColor: "#202020"
    };
    res = await fetch('https://walletobjects.googleapis.com/walletobjects/v1/genericClass', {
      method: 'POST', headers, body: JSON.stringify(body)
    });
    return res.status === 200;
  }
  return false;
}

// Create Google Save URL (JWT)
async function createGoogleSaveUrl(payloadObjId, person) {
  const classId = `${GOOGLE.issuerId}.${GOOGLE.classSuffix}`;
  const objectId = `${GOOGLE.issuerId}.${payloadObjId}`;

  const auth = new GoogleAuth({
    credentials: { 
      client_email: GOOGLE.saEmail, 
      private_key: GOOGLE.saPrivateKey 
    },
    scopes: ['https://www.googleapis.com/auth/wallet_object.issuer']
  });
  const client = await auth.getClient();

  await ensureGoogleGenericClass(client, classId);

  const jwtPayload = {
    iss: GOOGLE.saEmail,
    aud: 'google',
    typ: 'savetowallet',
    payload: {
      genericObjects: [{
        id: objectId,
        classId,
        hexBackgroundColor: '#202020',
        logo: { sourceUri: { uri: `${BASE_URL}/assets/logo.png` } },
        cardTitle: { defaultValue: { language: 'it', value: person.company || 'Business Card' } },
        subheader: { defaultValue: { language: 'it', value: person.role || '' } },
        header: { defaultValue: { language: 'it', value: person.name || '' } },
        heroImage: { sourceUri: { uri: `${BASE_URL}/assets/icon.png` } },
        barcode: { type: 'QR_CODE', value: person.qrPayload },
        textModulesData: [
          { header: 'Telefono', body: person.phone || '' },
          { header: 'Email', body: person.email || '' },
          { header: 'Sito', body: person.website || '' }
        ]
      }]
    }
  };

  const token = jwt.sign(jwtPayload, GOOGLE.saPrivateKey, { algorithm: 'RS256' });
  return `https://pay.google.com/gp/v/save/${token}`;
}

// Route: create pass for both platforms
app.post('/create-pass', async (req, res) => {
  try {
    const { name, role, company, phone, email, website, brandColor = '#202020', logoText = 'Business Card' } = req.body || {};

    if (!name || !role || !company || !phone || !email) {
      return res.json({ error: 'Compila tutti i campi obbligatori: nome, ruolo, azienda, telefono, email.' });
    }

    // Build QR payload (vCard-like link or URL)
    const payload = JSON.stringify({
      name, role, company, phone, email, website
    });
    const qrDataUrl = await QRCode.toDataURL(payload);

// --- APPLE PASS (.pkpass) ---
const certificates = {
  wwdr: fs.readFileSync(APPLE.wwdrPath),
  signerCert: fs.readFileSync(APPLE.certPath, 'utf8'),
  signerKey: fs.readFileSync(APPLE.keyPath, 'utf8'),
};

// helper: normalizza colore in formato accettato da Apple (rgb)
function hexToRgbCss(hex) {
  try {
    const h = hex.replace('#','').trim();
    const bigint = parseInt(h, 16);
    const r = (bigint >> 16) & 255;
    const g = (bigint >> 8) & 255;
    const b = bigint & 255;
    return `rgb(${r},${g},${b})`;
  } catch { return 'rgb(32,32,32)'; }
}

// Crea istanza PKPass - PRIMA SOLO I CERTIFICATI
const pass = new PKPass({}, certificates);

// POI imposta le proprietà del pass
pass.type = 'generic';
pass.serialNumber = uuidv4();
pass.description = 'Business Card';
pass.organizationName = company;
pass.passTypeIdentifier = APPLE.passTypeIdentifier;
pass.teamIdentifier = APPLE.teamIdentifier;
pass.backgroundColor = hexToRgbCss(brandColor || '#202020');
pass.labelColor = 'rgb(255,255,255)';
pass.foregroundColor = 'rgb(255,255,255)';
pass.logoText = logoText;

// Aggiungi i campi
pass.primaryFields.push({ key: 'name', label: 'NOME', value: String(name) });
pass.secondaryFields.push(
  { key: 'role', label: 'RUOLO', value: String(role) },
  { key: 'company', label: 'AZIENDA', value: String(company) }
);
pass.auxiliaryFields.push(
  { key: 'phone', label: 'TELEFONO', value: String(phone) },
  { key: 'email', label: 'EMAIL', value: String(email) }
);
pass.backFields.push({ key: 'website', label: 'SITO', value: String(website || '') });

// Aggiungi barcode
pass.setBarcodes({
  message: payload,
  format: 'PKBarcodeFormatQR',
  messageEncoding: 'iso-8859-1'
});

// Assets: icon e icon@2x sono importanti
pass.addBuffer('icon.png', fs.readFileSync(path.join(assetsDir, 'icon.png')));
pass.addBuffer('icon@2x.png', fs.readFileSync(path.join(assetsDir, 'icon@2x.png')));
if (fs.existsSync(path.join(assetsDir, 'logo.png'))) {
  pass.addBuffer('logo.png', fs.readFileSync(path.join(assetsDir, 'logo.png')));
}
if (fs.existsSync(path.join(assetsDir, 'logo@2x.png'))) {
  pass.addBuffer('logo@2x.png', fs.readFileSync(path.join(assetsDir, 'logo@2x.png')));
}

// Genera buffer e salva
const fileId = uuidv4();
const outfile = path.join(passesDir, `${fileId}.pkpass`);
const buf = await pass.getAsBuffer();
fs.writeFileSync(outfile, buf);

    // --- GOOGLE SAVE LINK ---
    const androidSaveUrl = await createGoogleSaveUrl(`businesscard-${fileId}`, {
      name, role, company, phone, email, website, qrPayload: payload
    });

    const iosDownloadUrl = `${BASE_URL}/download/pkpass/${fileId}`;

    res.json({ iosDownloadUrl, androidSaveUrl, qrDataUrl });
  } catch (err) {
    console.error(err);
    res.json({ error: 'Errore durante la generazione del pass. Controlla i certificati e le variabili .env.' });
  }
});

// Serve .pkpass con header compatibili iOS
app.get('/download/pkpass/:id', (req, res) => {
  const file = path.join(__dirname, 'passes', `${req.params.id}.pkpass`);
  if (!fs.existsSync(file)) return res.status(404).send('Not found');

  const stat = fs.statSync(file);
  const buf = fs.readFileSync(file);

  console.log(`[PKPASS] Serving ${req.params.id}.pkpass, size=${stat.size} bytes`);

  res.setHeader('Content-Type', 'application/vnd.apple.pkpass');
  res.setHeader('Content-Disposition', 'inline; filename="businesscard.pkpass"');
  res.setHeader('Content-Transfer-Encoding', 'binary');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Length', stat.size);
  res.status(200).end(buf);
});

// Serve assets (logo/icon) statically
app.use('/assets', express.static(path.join(__dirname, 'assets')));

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
