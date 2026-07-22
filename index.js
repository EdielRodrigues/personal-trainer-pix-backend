'use strict';

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const admin = require('firebase-admin');

const app = express();

app.use(cors({
  origin: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-Id', 'X-Signature']
}));
app.use(express.json({ limit: '1mb' }));

function initializeFirebase() {
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  const databaseURL = process.env.FIREBASE_DATABASE_URL;

  if (!raw) throw new Error('FIREBASE_SERVICE_ACCOUNT_JSON não configurado.');
  if (!databaseURL) throw new Error('FIREBASE_DATABASE_URL não configurado.');

  let serviceAccount;
  try {
    serviceAccount = JSON.parse(raw);
  } catch {
    throw new Error('FIREBASE_SERVICE_ACCOUNT_JSON inválido. Cole o JSON completo da conta de serviço.');
  }

  if (serviceAccount.private_key) {
    serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');
  }

  if (!admin.apps.length) {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      databaseURL
    });
  }
}

initializeFirebase();
const db = admin.database();

const PLANS = {
  mensal: { name: 'Plano Mensal', value: 19.90, days: 30 },
  trimestral: { name: 'Plano Trimestral', value: 49.90, days: 90 },
  anual: { name: 'Plano Anual', value: 149.90, days: 365 },
  vitalicio: { name: 'Acesso Vitalício', value: 299.90, days: 36500 }
};

function mpToken() {
  const token = process.env.MERCADO_PAGO_ACCESS_TOKEN;
  if (!token) throw new Error('MERCADO_PAGO_ACCESS_TOKEN não configurado.');
  return token;
}

function onlyNumbers(value) {
  return String(value || '').replace(/\D/g, '');
}

function splitName(fullName) {
  const parts = String(fullName || 'Cliente').trim().split(/\s+/).filter(Boolean);
  return {
    firstName: parts[0] || 'Cliente',
    lastName: parts.length > 1 ? parts.slice(1).join(' ') : 'Cliente'
  };
}

async function mpRequest(path, options = {}) {
  const response = await fetch(`https://api.mercadopago.com${path}`, {
    ...options,
    headers: {
      Authorization: `Bearer ${mpToken()}`,
      'Content-Type': 'application/json',
      Accept: 'application/json',
      ...(options.headers || {})
    }
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    console.error('Mercado Pago:', response.status, data);
    throw new Error(data.message || data.error || `Erro Mercado Pago (${response.status}).`);
  }
  return data;
}

async function authenticate(req, res, next) {
  try {
    const header = String(req.headers.authorization || '');
    if (!header.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Token não informado.' });
    }
    req.user = await admin.auth().verifyIdToken(header.slice(7).trim());
    return next();
  } catch (error) {
    console.error('Autenticação:', error.message);
    return res.status(401).json({ error: 'Sessão inválida ou expirada.' });
  }
}

function paymentIdFromRequest(req) {
  return String(
    req.query['data.id'] ||
    req.query.id ||
    req.body?.data?.id ||
    req.body?.id ||
    ''
  ).trim();
}

function validateWebhookSignature(req, dataId) {
  const secret = String(process.env.MERCADO_PAGO_WEBHOOK_SECRET || '');
  if (!secret) {
    console.warn('Webhook secret ainda não configurado. Assinatura não validada.');
    return true;
  }

  const xSignature = String(req.headers['x-signature'] || '');
  const xRequestId = String(req.headers['x-request-id'] || '');
  if (!xSignature || !xRequestId || !dataId) return false;

  let ts = '';
  let v1 = '';
  for (const part of xSignature.split(',')) {
    const [key, value] = part.trim().split('=');
    if (key === 'ts') ts = value;
    if (key === 'v1') v1 = value;
  }
  if (!ts || !v1) return false;

  const manifest = `id:${dataId};request-id:${xRequestId};ts:${ts};`;
  const calculated = crypto.createHmac('sha256', secret).update(manifest).digest('hex');
  const a = Buffer.from(v1, 'utf8');
  const b = Buffer.from(calculated, 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

async function syncPayment(payment, localPayment) {
  const paymentId = String(payment.id);
  const now = new Date().toISOString();
  const updates = {
    status: payment.status || 'unknown',
    statusDetail: payment.status_detail || '',
    updatedAt: now
  };

  if (payment.status === 'approved' && localPayment.status !== 'approved') {
    const plan = PLANS[localPayment.planId];
    if (!plan) throw new Error(`Plano ${localPayment.planId} não encontrado.`);

    const userRef = db.ref(`users/${localPayment.userId}`);
    const userData = (await userRef.once('value')).val() || {};
    let base = new Date();
    if (userData.expiresAt) {
      const current = new Date(userData.expiresAt);
      if (!Number.isNaN(current.getTime()) && current > base) base = current;
    }
    const expiration = new Date(base.getTime() + plan.days * 86400000);
    updates.approvedAt = now;

    await userRef.update({
      status: 'ativo',
      plan: localPayment.planId,
      planName: plan.name,
      expiresAt: expiration.toISOString(),
      lastPaymentId: paymentId,
      updatedAt: now
    });
  }

  await db.ref(`payments/${paymentId}`).update(updates);
  return updates;
}

app.get('/', (req, res) => {
  res.json({ online: true, service: 'Personal Trainer Pix', timestamp: new Date().toISOString() });
});

app.get('/health', (req, res) => {
  res.json({
    success: true,
    firebase: true,
    mercadoPagoToken: Boolean(process.env.MERCADO_PAGO_ACCESS_TOKEN),
    webhookSecret: Boolean(process.env.MERCADO_PAGO_WEBHOOK_SECRET),
    timestamp: new Date().toISOString()
  });
});

app.post('/createPix', authenticate, async (req, res) => {
  try {
    const planId = String(req.body.planId || '').trim();
    const plan = PLANS[planId];
    if (!plan) return res.status(400).json({ error: 'Plano inválido.' });

    const profile = (await db.ref(`users/${req.user.uid}`).once('value')).val();
    if (!profile) return res.status(404).json({ error: 'Cadastro do usuário não encontrado.' });

    const email = profile.email || req.user.email || '';
    const cpf = onlyNumbers(profile.cpf);
    if (!email) return res.status(400).json({ error: 'E-mail não cadastrado.' });
    if (cpf.length !== 11) return res.status(400).json({ error: 'CPF inválido ou não cadastrado.' });

    const { firstName, lastName } = splitName(profile.name);
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString();
    const externalReference = `${req.user.uid}|${planId}`;

    const payment = await mpRequest('/v1/payments', {
      method: 'POST',
      headers: { 'X-Idempotency-Key': crypto.randomUUID() },
      body: JSON.stringify({
        transaction_amount: Number(plan.value),
        description: `Personal Trainer Avançado Pro - ${plan.name}`,
        payment_method_id: 'pix',
        date_of_expiration: expiresAt,
        external_reference: externalReference,
        payer: {
          email,
          first_name: firstName,
          last_name: lastName,
          identification: { type: 'CPF', number: cpf }
        },
        metadata: {
          firebase_uid: req.user.uid,
          plan_id: planId,
          plan_name: plan.name
        }
      })
    });

    const transaction = payment.point_of_interaction?.transaction_data || {};
    const record = {
      userId: req.user.uid,
      userName: profile.name || '',
      userEmail: email,
      userCpfLast4: cpf.slice(-4),
      planId,
      planName: plan.name,
      amount: Number(plan.value),
      status: payment.status || 'pending',
      statusDetail: payment.status_detail || '',
      mercadoPagoId: String(payment.id),
      qrCode: transaction.qr_code || '',
      qrCodeBase64: transaction.qr_code_base64 || '',
      ticketUrl: transaction.ticket_url || '',
      externalReference: payment.external_reference || externalReference,
      createdAt: new Date().toISOString(),
      expiresAt,
      updatedAt: new Date().toISOString()
    };

    await db.ref(`payments/${payment.id}`).set(record);
    res.status(201).json({ success: true, payment: { id: String(payment.id), ...record } });
  } catch (error) {
    console.error('createPix:', error);
    res.status(500).json({ error: error.message || 'Não foi possível gerar o Pix.' });
  }
});

app.get('/paymentStatus', authenticate, async (req, res) => {
  try {
    const paymentId = String(req.query.id || '').trim();
    if (!paymentId) return res.status(400).json({ error: 'ID do pagamento não informado.' });

    const ref = db.ref(`payments/${paymentId}`);
    const local = (await ref.once('value')).val();
    if (!local || local.userId !== req.user.uid) {
      return res.status(404).json({ error: 'Pagamento não encontrado.' });
    }

    const payment = await mpRequest(`/v1/payments/${encodeURIComponent(paymentId)}`);
    await syncPayment(payment, local);
    const updated = (await ref.once('value')).val();
    res.json({ success: true, payment: { id: paymentId, ...updated } });
  } catch (error) {
    console.error('paymentStatus:', error);
    res.status(500).json({ error: error.message || 'Não foi possível consultar o pagamento.' });
  }
});

app.get('/latestPayment', authenticate, async (req, res) => {
  try {
    const snapshot = await db.ref('payments')
      .orderByChild('userId')
      .equalTo(req.user.uid)
      .limitToLast(1)
      .once('value');

    const all = snapshot.val() || {};
    const ids = Object.keys(all);
    if (!ids.length) return res.json({ success: true, payment: null });
    const id = ids[0];
    res.json({ success: true, payment: { id, ...all[id] } });
  } catch (error) {
    console.error('latestPayment:', error);
    res.status(500).json({ error: error.message || 'Não foi possível buscar o pagamento.' });
  }
});

app.post('/webhook', async (req, res) => {
  const paymentId = paymentIdFromRequest(req);
  try {
    if (!paymentId) return res.sendStatus(200);
    if (!validateWebhookSignature(req, paymentId)) return res.sendStatus(401);

    res.sendStatus(200);

    const payment = await mpRequest(`/v1/payments/${encodeURIComponent(paymentId)}`);
    const local = (await db.ref(`payments/${paymentId}`).once('value')).val();
    if (!local) return console.warn(`Pagamento ${paymentId} não encontrado no Firebase.`);
    await syncPayment(payment, local);
    console.log(`Pagamento ${paymentId} sincronizado: ${payment.status}`);
  } catch (error) {
    console.error('webhook:', error);
  }
});

app.use((req, res) => res.status(404).json({ error: 'Rota não encontrada.' }));

const PORT = Number(process.env.PORT || 10000);
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Personal Trainer Pix online na porta ${PORT}`);
});
