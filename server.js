// server.js — versione consolidata e "a prova di bomba"
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
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// Apple IDs (DEV: devono combaciare con il certificato!)
const APPLE = {
  passTypeIdentifier: process.env.APPLE_PASS_TYPE_IDENTIFIER,
  teamIdentifier: process.env.APPLE_TEAM_IDENTIFIER,
};

// Risolvi i path dei certificati (usa ENV o Secret Files noti)
const SIGNER_CERT_PATH = resolveFirstExisting([
  process.env.SIGNER_CERT_PATH,
  path.join(__dirname, 'certs', 'signerCert.pem'),
  '/etc/secrets/signerCert.pem',
]);

const SIGNER_KEY_PATH = resolveFirstExisting([
  process.env.SIGNER_KEY_PATH,
  path.join(__dirname, 'certs', 'signerKey.pem'),
  '/etc/secrets/signerKey.pem',
]);

const WWDR_PATH = resolveFirstExisting([
  process.env.APPLE_WWDR_PATH,
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
const googleCredsPath = process.env.GOOGLE_CREDENTIALS_PATH || null;
let googleCreds = {};
if (googleCredsPath) {
  try {
    googleCreds = JSON.parse(fs.readFileSync(googleCredsPath, 'utf8'));
    console.log('✅ GOOGLE_CREDENTIALS_PATH letto:', googleCredsPath);
    process.env.GOOGLE_APPLICATION_CREDENTIALS = googleCredsPath;
  } catch (e) {
    console.warn('⚠️ Impossibile leggere/parsare GOOGLE_CREDENTIALS_PATH:', googleCredsPath, e.message);
  }
}

const GOOGLE = {
  issuerId: process.env.GOOGLE_ISSUER_ID,
  classSuffix: process.env.GOOGLE_CLASS_SUFFIX || 'businesscard',
  saEmail: googleCreds.client_email || process.env.GOOGLE_SA_EMAIL || '',
  saPrivateKey: googleCreds.private_key || (process.env.GOOGLE_SA_PRIVATE_KEY || '').replace(/\\n/g, '\n'),
};

console.log('🔐 GW CONFIG →',
  '\n  issuerId:', GOOGLE.issuerId,
  '\n  classSuffix:', GOOGLE.classSuffix,
  '\n  saEmail:', GOOGLE.saEmail ? '✓' : '✗',
  '\n  saPrivateKey:', GOOGLE.saPrivateKey ? '✓ (presente)' : '✗ (mancante)'
);

// ──────────────────────────────────────────────────────────────
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Health route per Render
app.get('/health', (_req, res) => res.status(200).send('ok'));

// ──────────────────────────────────────────────────────────────
// Helper colori
function hexToRgbCss(hex) {
  try {
    const h = (hex || '#202020').replace('#','').trim();
    const n = parseInt(h, 16);
    const r = (n >> 16) & 255, g = (n >> 8) & 255, b = n & 255;
    return `rgb(${r},${g},${b})`;
  } catch { return 'rgb(32,32,32)'; }
}

// ──────────────────────────────────────────────────────────────
// Google: crea/usa la Generic Class
async function ensureGoogleGenericClass(authClient, classId) {
  const urlGet = `https://walletobjects.googleapis.com/walletobjects/v1/genericClass/${encodeURIComponent(classId)}`;

  console.log('GW → Verifico classe:', classId);

  try {
    const r = await authClient.request({ url: urlGet, method: 'GET' });
    if (r.status === 200) {
      console.log('✅ GW → Classe già esistente:', classId);
      return true;
    }
  } catch (e) {
    const status = e?.response?.status;
    const data = e?.response?.data;
    
    if (status === 404) {
      console.log('GW → Classe non trovata, procedo con creazione...');
    } else {
      console.error('❌ GW → Errore verifica classe:', status, JSON.stringify(data || e.message));
      return false;
    }
  }

  // Crea la classe
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
    console.log('✅ GW → Classe creata con successo, status:', r2.status);
    return r2.status === 200;
  } catch (e) {
    const status = e?.response?.status;
    const data = e?.response?.data;
    console.error('❌ GW → Errore creazione classe:', status, JSON.stringify(data || e.message));
    return false;
  }
}

// Crea o aggiorna un Generic Object
async function createOrUpsertGenericObject(authClient, classId, objectId, person) {
  console.log('GW → Creo/aggiorno object:', objectId);

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
    ],
    heroImage: { sourceUri: { uri: `${BASE_URL}/assets/icon.png` } },
    logo:      { sourceUri: { uri: `${BASE_URL}/assets/logo.png` } }
  };

  try {
    const r = await authClient.request({
      url: 'https://walletobjects.googleapis.com/walletobjects/v1/genericObject',
      method: 'POST',
      data
    });
    console.log('✅ GW → Object creato, status:', r.status);
    return true;
  } catch (e) {
    const status = e?.response?.status;
    const errorData = e?.response?.data;
    
    if (status === 409) {
      console.log('⚠️ GW → Object già esistente, tento update...');
      // Prova update
      try {
        const r2 = await authClient.request({
          url: `https://walletobjects.googleapis.com/walletobjects/v1/genericObject/${encodeURIComponent(objectId)}`,
          method: 'PUT',
          data
        });
        console.log('✅ GW → Object aggiornato, status:', r2.status);
        return true;
      } catch (e2) {
        console.error('❌ GW → Errore update object:', e2?.response?.status, JSON.stringify(e2?.response?.data || e2.message));
        return false;
      }
    }
    
    console.error('❌ GW → Errore creazione object:', status, JSON.stringify(errorData || e.message));
    return false;
  }
}

// Genera il Save URL per Google Wallet
async function createGoogleSaveUrl(payloadObjId, person) {
  if (!GOOGLE.issuerId || !GOOGLE.saEmail || !GOOGLE.saPrivateKey) {
    console.error('❌ GW → Configurazione mancante (issuerId, saEmail o saPrivateKey)');
    throw new Error('Configurazione Google Wallet incompleta');
  }

  console.log('🚀 GW → Inizio generazione Save URL');
  console.log('GW → issuerId:', GOOGLE.issuerId);
  console.log('GW → classSuffix:', GOOGLE.classSuffix);
  
  const classId = `${GOOGLE.issuerId}.${GOOGLE.classSuffix}`;
  const objectId = `${GOOGLE.issuerId}.${payloadObjId}`;
  
  console.log('GW → classId completo:', classId);
  console.log('GW → objectId completo:', objectId);

  try {
    // 1. Autentica
    console.log('GW → Step 1: Autenticazione...');
    const auth = new GoogleAuth({
      scopes: ['https://www.googleapis.com/auth/wallet_object.issuer'],
    });
    const client = await auth.getClient();
    console.log('✅ GW → Autenticazione completata');
    
    // 2. Assicurati che la classe esista
    console.log('GW → Step 2: Verifica/Creazione classe...');
    const classOk = await ensureGoogleGenericClass(client, classId);
    if (!classOk) {
      throw new Error('Impossibile creare/verificare la classe Google Wallet');
    }
    
    // 3. Crea l'object
    console.log('GW → Step 3: Creazione/Update object...');
    const objectOk = await createOrUpsertGenericObject(client, classId, objectId, person);
    if (!objectOk) {
      throw new Error('Impossibile creare/aggiornare l\'object Google Wallet');
    }

    // 4. Genera il JWT
    console.log('GW → Step 4: Generazione JWT...');
    const jwtPayload = {
      iss: GOOGLE.saEmail,
      aud: 'google',
      typ: 'savetowallet',
      iat: Math.floor(Date.now() / 1000),
      payload: {
        genericObjects: [{ id: objectId }]
      }
    };

    const token = jwt.sign(jwtPayload, GOOGLE.saPrivateKey, { algorithm: 'RS256' });
    const saveUrl = `https://pay.google.com/gp/v/save/${token}`;
    
    console.log('✅ GW → Save URL generato con successo');
    console.log('GW → URL:', saveUrl.substring(0, 80) + '...');
    
    return saveUrl;
    
  } catch (error) {
    console.error('❌ GW → Errore durante generazione Save URL:');
    console.error('   Messaggio:', error.message);
    console.error('   Stack:', error.stack);
    throw error;
  }
}

// ──────────────────────────────────────────────────────────────
// Crea pass per entrambe le piattaforme
app.post('/create-pass', async (req, res) => {
  try {
    const {
      name, role, company, phone, email, website,
      brandColor = '#202020', logoText = 'Business Card'
    } = req.body || {};

    console.log('📝 Richiesta creazione pass per:', name);

    if (!name || !role || !company || !phone || !email) {
      return res.json({ error: 'Compila nome, ruolo, azienda, telefono, email.' });
    }
    if (!APPLE.passTypeIdentifier || !APPLE.teamIdentifier) {
      return res.json({ error: 'Config Apple mancante: APPLE_PASS_TYPE_IDENTIFIER / APPLE_TEAM_IDENTIFIER.' });
    }

    // QR con payload "biglietto"
    const payload = JSON.stringify({ name, role, company, phone, email, website });
    const qrDataUrl = await QRCode.toDataURL(payload);

    // Verifica presenza cert Apple
    if (!SIGNER_CERT_PATH || !SIGNER_KEY_PATH || !WWDR_PATH) {
      return res.json({ error: 'Certificati Apple non disponibili lato server. Controlla Secret Files/ENV (vedi log PATHS).' });
    }

    console.log('🍎 Generazione Apple Pass...');

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

    // tipo e campi
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

    pass.setBarcodes([{
      format: 'PKBarcodeFormatQR',
      message: payload,
      messageEncoding: 'iso-8859-1'
    }]);

    // Asset obbligatori
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

    console.log('✅ Apple Pass creato:', fileId);

    // ── GOOGLE WALLET
    let androidSaveUrl = null;
    let androidError = null;
    
    console.log('🤖 Generazione Google Wallet...');
    try {
      androidSaveUrl = await createGoogleSaveUrl(`businesscard-${fileId}`, {
        name, role, company, phone, email, website, qrPayload: payload
      });
      console.log('✅ Google Wallet URL generato con successo');
    } catch (e) {
      androidError = e.message;
      console.error('❌ Google Wallet errore:', e.message);
      console.error('Stack:', e.stack);
    }

    const iosDownloadUrl = `${BASE_URL}/download/pkpass/${fileId}`;
    
    console.log('📦 Risposta finale:');
    console.log('  iOS URL:', iosDownloadUrl);
    console.log('  Android URL:', androidSaveUrl ? '✓' : '✗');
    console.log('  Android Error:', androidError || 'nessuno');

    return res.json({ 
      iosDownloadUrl, 
      androidSaveUrl, 
      androidError,
      qrDataUrl 
    });

  } catch (err) {
    console.error('❌ ERR /create-pass:', err);
    console.error('Stack:', err.stack);
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
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📍 BASE_URL: ${BASE_URL}`);
});
