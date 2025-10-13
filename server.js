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

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// --- Apple Wallet config ---
const APPLE = {
  passTypeIdentifier: process.env.APPLE_PASS_TYPE_IDENTIFIER,
  teamIdentifier: process.env.APPLE_TEAM_IDENTIFIER,
  p12Path: process.env.APPLE_P12_PATH || './certs/pass.p12',
  p12Password: process.env.APPLE_P12_PASSWORD,
  wwdrPath: process.env.APPLE_WWDR_PATH || './certs/wwdr.cer'
};

// --- Google Wallet config ---
const GOOGLE = {
  issuerId: process.env.GOOGLE_ISSUER_ID,
  classSuffix: process.env.GOOGLE_CLASS_SUFFIX || 'businesscard',
  saEmail: process.env.GOOGLE_SA_EMAIL,
  saPrivateKey: (process.env.GOOGLE_SA_PRIVATE_KEY || '').replace(/\\n/g, '\n')
};

// Simple validation check
function assertEnv() {
  const missing = [];
  if (!APPLE.passTypeIdentifier) missing.push('APPLE_PASS_TYPE_IDENTIFIER');
  if (!APPLE.teamIdentifier) missing.push('APPLE_TEAM_IDENTIFIER');
  if (!APPLE.p12Path || !fs.existsSync(APPLE.p12Path)) missing.push('APPLE_P12_PATH (file mancante)');
  if (!APPLE.p12Password) missing.push('APPLE_P12_PASSWORD');
  if (!APPLE.wwdrPath || !fs.existsSync(APPLE.wwdrPath)) console.warn('[WARN] APPLE_WWDR_PATH non trovato: alcune librerie potrebbero richiederlo.');
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
    credentials: { client_email: GOOGLE.saEmail, private_key: GOOGLE.saPrivateKey },
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

  const token = jwt.sign(jwtPayload, GOOGLE.saPrivateKey, { algorithm: 'RS256', keyid: undefined, issuer: GOOGLE.saEmail });
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
  signerCert: fs.readFileSync(APPLE.p12Path),
  signerKey: fs.readFileSync(APPLE.p12Path),
  signerKeyPassphrase: APPLE.p12Password
};

const passProps = {
  formatVersion: 1,
  description: 'Business Card',
  organizationName: company,
  teamIdentifier: APPLE.teamIdentifier,
  passTypeIdentifier: APPLE.passTypeIdentifier,
  serialNumber: uuidv4(),
  backgroundColor: brandColor,
  labelColor: '#ffffff',
  foregroundColor: '#ffffff',
  logoText: logoText,

  // tipo "generic" con i campi principali
  generic: {
    primaryFields: [
      { key: 'name', label: 'NOME', value: name }
    ],
    secondaryFields: [
      { key: 'role', label: 'RUOLO', value: role },
      { key: 'company', label: 'AZIENDA', value: company }
    ],
    auxiliaryFields: [
      { key: 'phone', label: 'TELEFONO', value: phone },
      { key: 'email', label: 'EMAIL', value: email }
    ],
    backFields: [
      { key: 'website', label: 'SITO', value: website || '' }
    ]
  }
};

// Crea istanza PKPass “da zero”
const pass = new PKPass({}, certificates, passProps);

// Aggiunge le immagini (possono essere placeholder, meglio sostituirle in /assets)
pass.addBuffer('icon.png', fs.readFileSync(path.join(assetsDir, 'icon.png')));
pass.addBuffer('logo.png', fs.readFileSync(path.join(assetsDir, 'logo.png')));

// Imposta il QR
pass.setBarcodes([{
  format: 'PKBarcodeFormatQR',
  message: payload,
  messageEncoding: 'iso-8859-1'
}]);

const fileId = uuidv4();
const outfile = path.join(passesDir, `${fileId}.pkpass`);
const buf = await pass.getAsBuffer(); // << importante: getAsBuffer()
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

// Serve .pkpass with correct headers
app.get('/download/pkpass/:id', (req, res) => {
  const file = path.join(__dirname, 'passes', `${req.params.id}.pkpass`);
  if (!fs.existsSync(file)) return res.status(404).send('Not found');
  res.setHeader('Content-Type', 'application/vnd.apple.pkpass');
  res.setHeader('Content-Disposition', 'attachment; filename="businesscard.pkpass"');
  fs.createReadStream(file).pipe(res);
});

// Serve assets (logo/icon) statically
app.use('/assets', express.static(path.join(__dirname, 'assets')));

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
