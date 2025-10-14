// server.js — versione consolidata e “a prova di bomba”
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import QRCode from 'qrcode';
import { v4 as uuidv4 } from 'uuid';
import jwt from 'jsonwebtoken';
import { GoogleAuth } from 'google-auth-library';
import fs from 'fs';
import { PKPass } from 'passkit-generator';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ──────────────────────────────────────────────────────────────
// Helper: risolvi il primo path esistente
function resolveFirstExisting(paths) {
  for (const p of paths) {
    if (!p) continue;
    try { if (fs.existsSync(p)) return p; } catch {}
  }
  return null;
}

// ──────────────────────────────────────────────────────────────
// Cartelle utili
const passesDir = path.join(__dirname, 'passes');
const assetsDir = path.join(__dirname, 'assets');
if (!fs.existsSync(passesDir)) fs.mkdirSync(passesDir, { recursive: true });

// ──────────────────────────────────────────────────────────────
// ENV base
const PORT = process.env.PORT || 3000; // Render passa la porta via env; NON impostarla tu
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// Apple IDs (DEV: devono combaciare con il certificato!)
const APPLE = {
  passTypeIdentifier: process.env.APPLE_PASS_TYPE_IDENTIFIER,
  teamIdentifier: process.env.APPLE_TEAM_IDENTIFIER,
};

// Risolvi i path dei certificati (usa ENV o Secret Files noti)
const SIGNER_CERT_PATH = resolveFirstExisting([
  process.env.SIGNER_CERT_PATH,                    // es. /etc/secrets/signerCert.pem o ./certs/signerCert.pem
  path.join(__dirname, 'certs', 'signerCert.pem'),
  '/etc/secrets/signerCert.pem',
]);

const SIGNER_KEY_PATH = resolveFirstExisting([
  process.env.SIGNER_KEY_PATH,                     // es. /etc/secrets/signerKey.pem o ./certs/signerKey.pem
  path.join(__dirname, 'certs', 'signerKey.pem'),
  '/etc/secrets/signerKey.pem',
]);

const WWDR_PATH = resolveFirstExisting([
  process.env.APPLE_WWDR_PATH,                     // CONSIGLIATO PEM (wwdr.pem)
  path.join(__dirname, 'certs', 'wwdr.pem'),
  '/etc/secrets/wwdr.pem',
  '/etc/secrets/wwdr.cer',
  path.join(__dirname, 'certs', 'wwdr.cer'),
]);

console.log('🔎 PATHS →',
  '\n  SIGNER_CERT_PATH:', SIGNER_CERT_PATH,
  '\n  SIGNER_KEY_PATH :', SIGNER_KEY_PATH,
  '\n  WWDR_PATH       :', WWDR_PATH
);

// ──────────────────────────────────────────────────────────────
// Google Wallet config
// Preferisco leggere tutto il JSON da un Secret File (GOOGLE_CREDENTIALS_PATH).
// In alternativa, puoi usare GOOGLE_SA_EMAIL + GOOGLE_SA_PRIVATE_KEY da ENV.
const googleCredsPath = process.env.GOOGLE_CREDENTIALS_PATH || null;
let googleCreds = {};
if (googleCredsPath) {
  try {
    googleCreds = JSON.parse(fs.readFileSync(googleCredsPath, 'utf8'));
    console.log('✅ GOOGLE_CREDENTIALS_PATH letto:', googleCredsPath);
    // 👉 forza anche l'ENV standard usata da GoogleAuth
    process.env.GOOGLE_APPLICATION_CREDENTIALS = googleCredsPath;
  } catch (e) {
    console.warn('⚠️ Impossibile leggere/parsare GOOGLE_CREDENTIALS_PATH:', googleCredsPath, e.message);
  }
}

const GOOGLE = {
  issuerId: process.env.GOOGLE_ISSUER_ID,                         // numero lungo dell’emittente
  classSuffix: process.env.GOOGLE_CLASS_SUFFIX || 'businesscard',
  saEmail: googleCreds.client_email || process.env.GOOGLE_SA_EMAIL || '',
  saPrivateKey: googleCreds.private_key || (process.env.GOOGLE_SA_PRIVATE_KEY || '').replace(/\\n/g, '\n'),
};

// ──────────────────────────────────────────────────────────────
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Health route per Render
app.get('/health', (_req, res) => res.status(200).send('ok'));

// ──────────────────────────────────────────────────────────────
// Helper colori (alcune versioni del lib preferiscono rgb())
function hexToRgbCss(hex) {
  try {
    const h = (hex || '#202020').replace('#','').trim();
    const n = parseInt(h, 16);
    const r = (n >> 16) & 255, g = (n >> 8) & 255, b = n & 255;
    return `rgb(${r},${g},${b})`;
  } catch { return 'rgb(32,32,32)'; }
}

// ──────────────────────────────────────────────────────────────
// Google: crea/usa la Generic Class e genera il Save Link
async function ensureGoogleGenericClass(authClient, classId) {
  const urlGet = `https://walletobjects.googleapis.com/walletobjects/v1/genericClass/${encodeURIComponent(classId)}`;

  try {
    // usa il client autenticato della GoogleAuth (niente fetch né header manuali)
    const r = await authClient.request({ url: urlGet, method: 'GET' });
    if (r.status === 200) {
      console.log('GW → class esiste:', classId);
      return true;
    }
  } catch (e) {
    const status = e?.response?.status;
    const data = e?.response?.data;
    console.warn('GW → getClass error:', status, JSON.stringify(data || e.message));
    if (status !== 404) return false; // 401/403 o altro → abort
  }

  // Se 404, proviamo a crearla
  const body = {
    id: classId,
    title: 'Business Card',
    issuerName: 'Your Brand',
    hexBackgroundColor: '#202020',
    reviewStatus: 'UNDER_REVIEW'
  };

  try {
    const r2 = await authClient.request({
      url: 'https://walletobjects.googleapis.com/walletobjects/v1/genericClass',
      method: 'POST',
      data: body
    });
    console.log('GW → createClass status:', r2.status);
    return r2.status === 200;
  } catch (e) {
    const status = e?.response?.status;
    const data = e?.response?.data;
    console.warn('GW → createClass error:', status, JSON.stringify(data || e.message));
    return false;
  }
}


console.log('GW DIAG → GOOGLE_APPLICATION_CREDENTIALS:', process.env.GOOGLE_APPLICATION_CREDENTIALS);
console.log('GW DIAG → has JSON file:', fs.existsSync(process.env.GOOGLE_APPLICATION_CREDENTIALS || ''));
console.log('GW DIAG → issuerId:', GOOGLE.issuerId);

// Crea o “upserta” un Generic Object prima di generare il link di salvataggio
async function createOrUpsertGenericObject(authClient, classId, objectId, person) {
  const data = {
    id: objectId,
    classId,
    hexBackgroundColor: '#202020',
    header:    { defaultValue: { language: 'it', value: person.name || '' } },
    subheader: { defaultValue: { language: 'it', value: person.role || '' } },
    cardTitle: { defaultValue: { language: 'it', value: person.company || 'Business Card' } },
    barcode: { type: 'QR_CODE', value: person.qrPayload || 'N/A' },
    textModulesData: [
      { header: 'Telefono', body: person.phone || '' },
      { header: 'Email',    body: person.email || ''  },
      { header: 'Sito',     body: person.website || '' }
    ]
    // ⚠️ Per ora niente immagini per evitare errori (riattiva dopo che tutto funziona)
    // ,heroImage: { sourceUri: { uri: `${BASE_URL}/assets/icon.png` } },
    // ,logo:      { sourceUri: { uri: `${BASE_URL}/assets/logo.png` } }
  };

  try {
    const r = await authClient.request({
      url: 'https://walletobjects.googleapis.com/walletobjects/v1/genericObject',
      method: 'POST',
      data
    });
    console.log('GW → insertObject status:', r.status);
    return true;
  } catch (e) {
    const status = e?.response?.status;
    const msg = e?.response?.data || e?.message;
    if (status === 409) { // già esiste → va bene
      console.log('GW → object già esistente:', objectId);
      return true;
    }
    console.warn('GW → insertObject error:', status, JSON.stringify(msg));
    return false;
  }
}


async function createGoogleSaveUrl(payloadObjId, person) {
  if (!GOOGLE.issuerId || !GOOGLE.saEmail || !GOOGLE.saPrivateKey) return null;

  console.log('GW → issuerId:', GOOGLE.issuerId, 'classSuffix:', GOOGLE.classSuffix);
  const classId = `${GOOGLE.issuerId}.${GOOGLE.classSuffix}`;
  console.log('GW → classId:', classId);
  const objectId = `${GOOGLE.issuerId}.${payloadObjId}`;

  const auth = new GoogleAuth({
  scopes: ['https://www.googleapis.com/auth/wallet_object.issuer'],
  });
  const client = await auth.getClient(); // <— questo 'client' passalo a ensureGoogleGenericClass
  const ok = await ensureGoogleGenericClass(client, classId);
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
        header:    { defaultValue: { language: 'it', value: person.name || '' } },
        subheader: { defaultValue: { language: 'it', value: person.role || '' } },
        cardTitle: { defaultValue: { language: 'it', value: person.company || 'Business Card' } },
        heroImage: { sourceUri: { uri: `${BASE_URL}/assets/icon.png` } },
        logo:      { sourceUri: { uri: `${BASE_URL}/assets/logo.png` } },
        barcode: { type: 'QR_CODE', value: person.qrPayload },
        textModulesData: [
          { header: 'Telefono', body: person.phone || '' },
          { header: 'Email',    body: person.email || ''  },
          { header: 'Sito',     body: person.website || '' }
        ]
      }]
    }
  };

  // firma senza keyid/issuer nelle options (iss è già nel payload)
  const token = jwt.sign(jwtPayload, GOOGLE.saPrivateKey, { algorithm: 'RS256' });
  return `https://pay.google.com/gp/v/save/${token}`;
}

// ──────────────────────────────────────────────────────────────
// Crea pass per entrambe le piattaforme
app.post('/create-pass', async (req, res) => {
  try {
    const {
      name, role, company, phone, email, website,
      brandColor = '#202020', logoText = 'Business Card'
    } = req.body || {};

    if (!name || !role || !company || !phone || !email) {
      return res.json({ error: 'Compila nome, ruolo, azienda, telefono, email.' });
    }
    if (!APPLE.passTypeIdentifier || !APPLE.teamIdentifier) {
      return res.json({ error: 'Config Apple mancante: APPLE_PASS_TYPE_IDENTIFIER / APPLE_TEAM_IDENTIFIER.' });
    }

    // QR con payload “biglietto”
    const payload = JSON.stringify({ name, role, company, phone, email, website });
    const qrDataUrl = await QRCode.toDataURL(payload);

    // Verifica presenza cert Apple
    if (!SIGNER_CERT_PATH || !SIGNER_KEY_PATH || !WWDR_PATH) {
      return res.json({ error: 'Certificati Apple non disponibili lato server. Controlla Secret Files/ENV (vedi log PATHS).' });
    }

    console.log('PASS IDS → passTypeIdentifier:', APPLE.passTypeIdentifier, 'teamIdentifier:', APPLE.teamIdentifier);

    // ── APPLE PASS (.pkpass)
    const certificates = {
      wwdr: fs.readFileSync(WWDR_PATH),
      signerCert: fs.readFileSync(SIGNER_CERT_PATH),
      signerKey: fs.readFileSync(SIGNER_KEY_PATH),
    };

    const pass = new PKPass({}, certificates, {
      formatVersion: 1,
      description: 'Business Card',
      organizationName: company,
      teamIdentifier: APPLE.teamIdentifier,
      passTypeIdentifier: APPLE.passTypeIdentifier,
      serialNumber: uuidv4(),
      backgroundColor: hexToRgbCss(brandColor),
      labelColor: 'rgb(255,255,255)',
      foregroundColor: 'rgb(255,255,255)',
      logoText,
    });

    // tipo e campi (imposta type PRIMA di toccare i campi)
    pass.type = 'generic';
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

    // barcode in ARRAY (iOS vuole array)
    pass.setBarcodes([{
      format: 'PKBarcodeFormatQR',
      message: payload,
      messageEncoding: 'iso-8859-1'
    }]);

    // Asset obbligatori: icon.png 29x29 & icon@2x.png 58x58
    const icon1 = path.join(assetsDir, 'icon.png');
    const icon2 = path.join(assetsDir, 'icon@2x.png');
    if (fs.existsSync(icon1)) pass.addBuffer('icon.png', fs.readFileSync(icon1));
    if (fs.existsSync(icon2)) pass.addBuffer('icon@2x.png', fs.readFileSync(icon2));
    const logo1 = path.join(assetsDir, 'logo.png');
    const logo2 = path.join(assetsDir, 'logo@2x.png');
    if (fs.existsSync(logo1)) pass.addBuffer('logo.png', fs.readFileSync(logo1));
    if (fs.existsSync(logo2)) pass.addBuffer('logo@2x.png', fs.readFileSync(logo2));

    const fileId = uuidv4();
    const outfile = path.join(passesDir, `${fileId}.pkpass`);
    const buf = await pass.getAsBuffer();
    fs.writeFileSync(outfile, buf);

    // ── GOOGLE: Save link (se configurato)
    let androidSaveUrl = null;
    try {
      androidSaveUrl = await createGoogleSaveUrl(`businesscard-${fileId}`, {
        name, role, company, phone, email, website, qrPayload: payload
      });
    } catch (e) {
      console.warn('Google Wallet non disponibile:', e.message);
    }

    const iosDownloadUrl = `${BASE_URL}/download/pkpass/${fileId}`;
    return res.json({ iosDownloadUrl, androidSaveUrl, qrDataUrl });

  } catch (err) {
    console.error('ERR /create-pass:', err);
    return res.json({ error: `Errore durante la generazione del pass: ${err?.message || 'unknown'}` });
  }
});

// ──────────────────────────────────────────────────────────────
// Download .pkpass con header compatibili iOS
app.get('/download/pkpass/:id', (req, res) => {
  const file = path.join(passesDir, `${req.params.id}.pkpass`);
  if (!fs.existsSync(file)) return res.status(404).send('Not found');

  const stat = fs.statSync(file);
  const buf = fs.readFileSync(file);
  console.log(`[PKPASS] Serving ${path.basename(file)}, size=${stat.size} bytes`);

  res.setHeader('Content-Type', 'application/vnd.apple.pkpass');
  res.setHeader('Content-Disposition', 'inline; filename="businesscard.pkpass"');
  res.setHeader('Content-Transfer-Encoding', 'binary');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Length', stat.size);
  return res.status(200).end(buf);
});

// ──────────────────────────────────────────────────────────────
app.use('/assets', express.static(path.join(__dirname, 'assets')));

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
