// server.js — versione completa con upload logo e campi multipli
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
import multer from 'multer';
import sharp from 'sharp';

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
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(passesDir)) fs.mkdirSync(passesDir, { recursive: true });
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

// Configurazione Multer per upload logo
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const uniqueName = `logo-${uuidv4()}${path.extname(file.originalname)}`;
    cb(null, uniqueName);
  }
});
const upload = multer({ 
  storage,
  limits: { fileSize: 2 * 1024 * 1024 }, // Max 2MB
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Solo immagini ammesse'));
    }
  }
});

// ──────────────────────────────────────────────────────────────
// ENV base
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// Apple IDs
const APPLE = {
  passTypeIdentifier: process.env.APPLE_PASS_TYPE_IDENTIFIER,
  teamIdentifier: process.env.APPLE_TEAM_IDENTIFIER,
};

// Risolvi i path dei certificati
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
// Helper: genera vCard con supporto multiplo per telefoni e indirizzi
function generateVCard(data) {
  const lines = [
    'BEGIN:VCARD',
    'VERSION:3.0',
    `FN:${data.name}`,
    `ORG:${data.company}`,
    `TITLE:${data.role}`
  ];

  // Aggiungi telefoni (supporto multiplo)
  if (data.phones && Array.isArray(data.phones)) {
    data.phones.forEach(phone => {
      if (phone.number) {
        const type = phone.type || 'WORK';
        lines.push(`TEL;TYPE=${type},VOICE:${phone.number}`);
      }
    });
  }

  // Email
  if (data.email) {
    lines.push(`EMAIL;TYPE=INTERNET:${data.email}`);
  }

  // Indirizzi (supporto multiplo)
  if (data.addresses && Array.isArray(data.addresses)) {
    data.addresses.forEach(addr => {
      if (addr.street || addr.city || addr.zip || addr.country) {
        // Formato: ADR;TYPE=WORK:;;street;city;state;zip;country
        const adrLine = `ADR;TYPE=${addr.type || 'WORK'}:;;${addr.street || ''};${addr.city || ''};${addr.state || ''};${addr.zip || ''};${addr.country || ''}`;
        lines.push(adrLine);
      }
    });
  }

  // Website
  if (data.website) {
    lines.push(`URL:${data.website}`);
  }

  lines.push('END:VCARD');
  return lines.join('\r\n');
}

// Helper: processa logo aziendale per Apple Wallet (icona e logo)
async function processCompanyLogo(logoPath, outputDir) {
  try {
    // Genera icon.png (29x29) e icon@2x.png (58x58)
    await sharp(logoPath)
      .resize(29, 29, { fit: 'cover' })
      .png()
      .toFile(path.join(outputDir, 'icon.png'));
    
    await sharp(logoPath)
      .resize(58, 58, { fit: 'cover' })
      .png()
      .toFile(path.join(outputDir, 'icon@2x.png'));

    // Genera logo.png (160x50) e logo@2x.png (320x100)
    await sharp(logoPath)
      .resize(160, 50, { fit: 'contain', background: { r: 0, g: 0, b: 0, alpha: 0 } })
      .png()
      .toFile(path.join(outputDir, 'logo.png'));
    
    await sharp(logoPath)
      .resize(320, 100, { fit: 'contain', background: { r: 0, g: 0, b: 0, alpha: 0 } })
      .png()
      .toFile(path.join(outputDir, 'logo@2x.png'));

    console.log('✅ Logo processato per Apple Wallet');
    return true;
  } catch (e) {
    console.error('❌ Errore processamento logo:', e.message);
    return false;
  }
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

  // Prepara textModulesData con telefoni e indirizzi
  const textModules = [];
  
  // Telefoni
  if (person.phones && Array.isArray(person.phones)) {
    person.phones.forEach(phone => {
      if (phone.number) {
        textModules.push({
          header: phone.type || 'Telefono',
          body: phone.number
        });
      }
    });
  }

  // Email
  if (person.email) {
    textModules.push({ header: 'Email', body: person.email });
  }

  // Indirizzi
  if (person.addresses && Array.isArray(person.addresses)) {
    person.addresses.forEach(addr => {
      if (addr.street || addr.city) {
        const fullAddr = [addr.street, addr.city, addr.zip, addr.country].filter(x => x).join(', ');
        textModules.push({
          header: addr.type || 'Indirizzo',
          body: fullAddr
        });
      }
    });
  }

  // Sito
  if (person.website) {
    textModules.push({ header: 'Sito', body: person.website });
  }

  const data = {
    id: objectId,
    classId,
    hexBackgroundColor: '#202020',
    header:    { defaultValue: { language: 'it', value: person.name || '' } },
    subheader: { defaultValue: { language: 'it', value: person.role || '' } },
    cardTitle: { defaultValue: { language: 'it', value: person.company || 'Business Card' } },
    barcode: { type: 'QR_CODE', value: person.qrPayload || 'N/A' },
    textModulesData: textModules
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
  const classId = `${GOOGLE.issuerId}.${GOOGLE.classSuffix}`;
  const objectId = `${GOOGLE.issuerId}.${payloadObjId}`;

  try {
    const auth = new GoogleAuth({
      scopes: ['https://www.googleapis.com/auth/wallet_object.issuer'],
    });
    const client = await auth.getClient();
    console.log('✅ GW → Autenticazione completata');
    
    const classOk = await ensureGoogleGenericClass(client, classId);
    if (!classOk) {
      throw new Error('Impossibile creare/verificare la classe Google Wallet');
    }
    
    const objectOk = await createOrUpsertGenericObject(client, classId, objectId, person);
    if (!objectOk) {
      throw new Error('Impossibile creare/aggiornare l\'object Google Wallet');
    }

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
    return saveUrl;
    
  } catch (error) {
    console.error('❌ GW → Errore durante generazione Save URL:', error.message);
    throw error;
  }
}

// ──────────────────────────────────────────────────────────────
// Upload logo endpoint
app.post('/upload-logo', upload.single('logo'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Nessun file caricato' });
    }

    const logoPath = req.file.path;
    const logoUrl = `${BASE_URL}/uploads/${req.file.filename}`;
    
    console.log('📤 Logo caricato:', logoUrl);
    
    return res.json({ 
      success: true, 
      logoPath: req.file.filename,
      logoUrl 
    });
  } catch (err) {
    console.error('❌ Errore upload logo:', err);
    return res.status(500).json({ error: err.message });
  }
});

// ──────────────────────────────────────────────────────────────
// Crea pass per entrambe le piattaforme
app.post('/create-pass', async (req, res) => {
  try {
    const {
      name, role, company, email, website,
      phones = [],        // Array di {type, number}
      addresses = [],     // Array di {type, street, city, zip, state, country}
      logoPath,           // Nome file logo caricato (opzionale)
      brandColor = '#202020', 
      logoText = 'Business Card'
    } = req.body || {};

    console.log('📝 Richiesta creazione pass per:', name);
    console.log('📞 Telefoni:', phones);
    console.log('📍 Indirizzi:', addresses);

    if (!name || !role || !company || !email) {
      return res.json({ error: 'Compila almeno nome, ruolo, azienda ed email.' });
    }
    if (!phones || phones.length === 0) {
      return res.json({ error: 'Aggiungi almeno un numero di telefono.' });
    }
    if (!APPLE.passTypeIdentifier || !APPLE.teamIdentifier) {
      return res.json({ error: 'Config Apple mancante.' });
    }

    // Genera vCard con tutti i dati
    const vCard = generateVCard({ name, role, company, email, website, phones, addresses });
    console.log('📇 vCard generato:', vCard.substring(0, 100) + '...');

    const qrDataUrl = await QRCode.toDataURL(vCard);

    // Verifica certificati Apple
    if (!SIGNER_CERT_PATH || !SIGNER_KEY_PATH || !WWDR_PATH) {
      return res.json({ error: 'Certificati Apple non disponibili.' });
    }

    console.log('🍎 Generazione Apple Pass...');

    // ── APPLE PASS (.pkpass)
    const certificates = {
      wwdr: fs.readFileSync(WWDR_PATH),
      signerCert: fs.readFileSync(SIGNER_CERT_PATH),
      signerKey: fs.readFileSync(SIGNER_KEY_PATH),
    };

    console.log('🔲 Creazione pass...');

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
      logoText
    });

    // Imposta tipo PRIMA di tutto
    pass.type = 'generic';
    
    // Imposta barcode SUBITO dopo, prima dei campi
    console.log('🔲 Impostazione barcode con setBarcodes([])...');
    console.log('   vCard length:', vCard.length);
    
    pass.setBarcodes([{
      format: 'PKBarcodeFormatQR',
      message: vCard,
      messageEncoding: 'iso-8859-1'
    }]);
    
    console.log('🔲 Barcode check:', pass.barcodes ? pass.barcodes.length : 0);

    // NON modificare più il barcode dopo questo punto!

    // Campi del pass
    pass.type = 'generic';
    pass.primaryFields.push({ key: 'name', label: 'NOME', value: String(name) });
    pass.secondaryFields.push(
      { key: 'role', label: 'RUOLO', value: String(role) },
      { key: 'company', label: 'AZIENDA', value: String(company) }
    );

    // Mostra primo telefono e email negli auxiliary fields
    if (phones[0]) {
      pass.auxiliaryFields.push({ 
        key: 'phone', 
        label: phones[0].type || 'TELEFONO', 
        value: String(phones[0].number) 
      });
    }
    pass.auxiliaryFields.push({ key: 'email', label: 'EMAIL', value: String(email) });

    // Back fields: altri telefoni, indirizzi, sito
    if (phones.length > 1) {
      phones.slice(1).forEach((phone, idx) => {
        pass.backFields.push({
          key: `phone_${idx + 2}`,
          label: phone.type || 'TELEFONO',
          value: String(phone.number)
        });
      });
    }

    if (addresses.length > 0) {
      addresses.forEach((addr, idx) => {
        const fullAddr = [addr.street, addr.city, addr.zip, addr.country].filter(x => x).join(', ');
        pass.backFields.push({
          key: `address_${idx + 1}`,
          label: addr.type || 'INDIRIZZO',
          value: fullAddr
        });
      });
    }

    if (website) {
      pass.backFields.push({ key: 'website', label: 'SITO', value: String(website) });
    }

    pass.backFields.push({ 
      key: 'qr_info', 
      label: 'QR CODE', 
      value: 'Scansiona il codice QR per salvare il contatto nella rubrica' 
    });

    // Processa logo aziendale se fornito
    const fileId = uuidv4();
    const tempLogoDir = path.join(uploadsDir, `temp-${fileId}`);
    fs.mkdirSync(tempLogoDir, { recursive: true });

    if (logoPath) {
      const uploadedLogoPath = path.join(uploadsDir, logoPath);
      if (fs.existsSync(uploadedLogoPath)) {
        await processCompanyLogo(uploadedLogoPath, tempLogoDir);
        
        // Aggiungi le immagini processate al pass
        const icon1 = path.join(tempLogoDir, 'icon.png');
        const icon2 = path.join(tempLogoDir, 'icon@2x.png');
        const logo1 = path.join(tempLogoDir, 'logo.png');
        const logo2 = path.join(tempLogoDir, 'logo@2x.png');
        
        if (fs.existsSync(icon1)) pass.addBuffer('icon.png', fs.readFileSync(icon1));
        if (fs.existsSync(icon2)) pass.addBuffer('icon@2x.png', fs.readFileSync(icon2));
        if (fs.existsSync(logo1)) pass.addBuffer('logo.png', fs.readFileSync(logo1));
        if (fs.existsSync(logo2)) pass.addBuffer('logo@2x.png', fs.readFileSync(logo2));
      }
    } else {
      // Usa logo di default se presente
      const icon1 = path.join(assetsDir, 'icon.png');
      const icon2 = path.join(assetsDir, 'icon@2x.png');
      const logo1 = path.join(assetsDir, 'logo.png');
      const logo2 = path.join(assetsDir, 'logo@2x.png');
      
      if (fs.existsSync(icon1)) pass.addBuffer('icon.png', fs.readFileSync(icon1));
      if (fs.existsSync(icon2)) pass.addBuffer('icon@2x.png', fs.readFileSync(icon2));
      if (fs.existsSync(logo1)) pass.addBuffer('logo.png', fs.readFileSync(logo1));
      if (fs.existsSync(logo2)) pass.addBuffer('logo@2x.png', fs.readFileSync(logo2));
    }

    console.log('✅ Pass configurato completamente');
    console.log('🔲 Barcode nel pass:', pass.barcode ? '✓' : '✗');
    console.log('🔲 Barcodes array:', pass.barcodes ? pass.barcodes.length : 0);

    const outfile = path.join(passesDir, `${fileId}.pkpass`);
    const buf = await pass.getAsBuffer();
    fs.writeFileSync(outfile, buf);

    // Pulizia file temporanei
    if (fs.existsSync(tempLogoDir)) {
      fs.rmSync(tempLogoDir, { recursive: true, force: true });
    }

    console.log('✅ Apple Pass creato:', fileId);

    // ── GOOGLE WALLET
    let androidSaveUrl = null;
    let androidError = null;
    
    console.log('🤖 Generazione Google Wallet...');
    try {
      androidSaveUrl = await createGoogleSaveUrl(`businesscard-${fileId}`, {
        name, role, company, email, website, phones, addresses, qrPayload: vCard
      });
      console.log('✅ Google Wallet URL generato');
    } catch (e) {
      androidError = e.message;
      console.error('❌ Google Wallet errore:', e.message);
    }

    const iosDownloadUrl = `${BASE_URL}/download/pkpass/${fileId}`;

    return res.json({ 
      iosDownloadUrl, 
      androidSaveUrl, 
      androidError,
      qrDataUrl 
    });

  } catch (err) {
    console.error('❌ ERR /create-pass:', err);
    return res.json({ error: `Errore: ${err?.message || 'unknown'}` });
  }
});

// ──────────────────────────────────────────────────────────────
// Download .pkpass
app.get('/download/pkpass/:id', (req, res) => {
  const file = path.join(passesDir, `${req.params.id}.pkpass`);
  if (!fs.existsSync(file)) return res.status(404).send('Not found');

  const stat = fs.statSync(file);
  const buf = fs.readFileSync(file);

  res.setHeader('Content-Type', 'application/vnd.apple.pkpass');
  res.setHeader('Content-Disposition', 'inline; filename="businesscard.pkpass"');
  res.setHeader('Content-Transfer-Encoding', 'binary');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Length', stat.size);
  return res.status(200).end(buf);
});

// ──────────────────────────────────────────────────────────────
app.use('/assets', express.static(path.join(__dirname, 'assets')));
app.use('/uploads', express.static(uploadsDir));

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📍 BASE_URL: ${BASE_URL}`);
});
