'use strict';

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { initializeApp, cert, getApps } = require('firebase-admin/app');
const { getDatabase } = require('firebase-admin/database');
const { getAuth } = require('firebase-admin/auth');

const app = express();
app.set('trust proxy', true);

app.use(cors({
  origin: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-Id', 'X-Signature']
}));
app.use(express.json({ limit: '1mb' }));

function initializeFirebase() {
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT || process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  const databaseURL = process.env.FIREBASE_DATABASE_URL;

  if (!raw) throw new Error('FIREBASE_SERVICE_ACCOUNT não configurado.');
  if (!databaseURL) throw new Error('FIREBASE_DATABASE_URL não configurado.');

  let serviceAccount;
  try {
    serviceAccount = JSON.parse(raw);
  } catch {
    throw new Error('FIREBASE_SERVICE_ACCOUNT inválido. Cole o JSON completo da conta de serviço.');
  }

  if (serviceAccount.private_key) {
    serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');
  }

  if (!getApps().length) {
    initializeApp({
      credential: cert(serviceAccount),
      databaseURL
    });
  }
}

initializeFirebase();
const db = getDatabase();
const auth = getAuth();

const PLANS = { mensal: { name: 'Finance IA Pro Mensal', value: 24.90, days: 30 } };

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
    req.user = await auth.verifyIdToken(header.slice(7).trim());
    return next();
  } catch (error) {
    console.error('Autenticação:', error.message);
    return res.status(401).json({ error: 'Sessão inválida ou expirada.' });
  }
}

async function authenticateAdmin(req, res, next) {
  return authenticate(req, res, async () => {
    try {
      const profile = (await db.ref(`users/${req.user.uid}`).once('value')).val();
      if (!['admin','owner'].includes(profile?.role)) return res.status(403).json({ error: 'Acesso permitido somente para proprietário ou administrador.' });
      req.adminProfile = profile;
      return next();
    } catch (error) {
      return res.status(500).json({ error: 'Não foi possível validar o administrador.' });
    }
  });
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

function normalizeReferralCode(value) { return String(value || '').trim().toUpperCase().replace(/[^A-Z0-9_-]/g, '').slice(0, 32); }
function makeReferralCode(uid) { return `PT${String(uid || '').replace(/[^a-zA-Z0-9]/g, '').slice(0, 10).toUpperCase()}`; }
function safeBaseUrl(value) { try { const u = new URL(String(value || '')); return `${u.origin}${u.pathname}`; } catch { return 'https://edielrodrigues.github.io/E-books/'; } }
async function awardReferralBonus(referredUid, paymentId, now) {
  const rootRef = db.ref();
  let awarded = false;
  await rootRef.transaction(root => {
    root = root || {};
    const users = root.users || {};
    const buyer = users[referredUid];
    if (!buyer || !buyer.referredByUid || buyer.referralBonusAwarded) return root;
    const referrerUid = buyer.referredByUid;
    if (referrerUid === referredUid || !users[referrerUid]) return root;
    root.referrals = root.referrals || {};
    root.referrals[referrerUid] = root.referrals[referrerUid] || {};
    const entry = root.referrals[referrerUid][referredUid] || {};
    if (entry.bonusAwarded) return root;
    const referrer = users[referrerUid];
    let base = Date.now();
    const currentExpiry = Date.parse(referrer.expiresAt || '');
    if (Number.isFinite(currentExpiry) && currentExpiry > base) base = currentExpiry;
    referrer.expiresAt = new Date(base + 86400000).toISOString();
    referrer.status = 'ativo';
    referrer.referralDaysEarned = Number(referrer.referralDaysEarned || 0) + 1;
    referrer.referralApprovedPayments = Number(referrer.referralApprovedPayments || 0) + 1;
    referrer.updatedAt = now;
    buyer.referralBonusAwarded = true;
    buyer.referralBonusPaymentId = paymentId;
    buyer.referralBonusAwardedAt = now;
    root.referrals[referrerUid][referredUid] = {...entry,status:'approved',bonusAwarded:true,bonusDays:1,paymentId,approvedAt:now,updatedAt:now};
    awarded = true;
    return root;
  });
  return awarded;
}

async function paymentRecordFromMercadoPago(payment) {
  const paymentId = String(payment.id || '');
  const metadata = payment.metadata || {};
  const externalParts = String(payment.external_reference || '').split('|');
  const userId = String(metadata.firebase_uid || externalParts[0] || '').trim();
  const planId = String(metadata.plan_id || externalParts[1] || 'mensal').trim();
  if (!paymentId || !userId) return null;

  const plan = PLANS[planId] || PLANS.mensal;
  const transaction = payment.point_of_interaction?.transaction_data || {};
  const now = new Date().toISOString();
  const record = {
    userId,
    planId,
    planName: metadata.plan_name || plan.name,
    amount: Number(payment.transaction_amount || plan.value),
    paymentMethod: payment.payment_type_id || 'pix',
    paymentMethodId: payment.payment_method_id || 'pix',
    status: payment.status || 'unknown',
    statusDetail: payment.status_detail || '',
    mercadoPagoId: paymentId,
    qrCode: transaction.qr_code || '',
    qrCodeBase64: transaction.qr_code_base64 || '',
    ticketUrl: transaction.ticket_url || '',
    externalReference: payment.external_reference || `${userId}|${planId}`,
    createdAt: payment.date_created || now,
    paymentExpiresAt: payment.date_of_expiration || null,
    updatedAt: now,
    recoveredByWebhook: true
  };
  await db.ref(`payments/${paymentId}`).update(record);
  return (await db.ref(`payments/${paymentId}`).once('value')).val();
}

async function syncPayment(payment, suppliedLocalPayment) {
  const paymentId = String(payment.id);
  const paymentRef = db.ref(`payments/${paymentId}`);
  let localPayment = suppliedLocalPayment || (await paymentRef.once('value')).val();
  if (!localPayment) localPayment = await paymentRecordFromMercadoPago(payment);
  if (!localPayment?.userId) throw new Error(`Pagamento ${paymentId} sem usuário vinculado.`);

  const now = new Date().toISOString();
  const remoteStatus = String(payment.status || 'unknown').toLowerCase();
  const plan = PLANS[localPayment.planId] || PLANS.mensal;

  // Uma transação na raiz impede que webhooks repetidos acrescentem 30 dias duas vezes.
  let accessGranted = false;
  let newExpiration = null;
  await db.ref().transaction(root => {
    root = root || {};
    root.payments = root.payments || {};
    root.users = root.users || {};
    const stored = root.payments[paymentId] || localPayment || {};
    const user = root.users[localPayment.userId] || {};
    const existingUserExpiry = Date.parse(user.subscriptionUntil || user.expiresAt || '');
    const wasApproved = Boolean(stored.accessGrantedAt) || (String(user.lastPaymentId || '') === paymentId && Number.isFinite(existingUserExpiry));

    Object.assign(stored, {
      status: remoteStatus,
      statusDetail: payment.status_detail || '',
      mercadoPagoId: paymentId,
      updatedAt: now,
      lastWebhookAt: now,
      lastMercadoPagoStatusAt: payment.date_last_updated || now
    });

    if (remoteStatus === 'approved') {
      stored.approvedAt = stored.approvedAt || payment.date_approved || now;
      stored.paidAt = stored.paidAt || payment.date_approved || now;
      if (!wasApproved) {
        let baseMs = Date.now();
        const currentExpiry = Date.parse(user.subscriptionUntil || user.expiresAt || '');
        if (Number.isFinite(currentExpiry) && currentExpiry > baseMs) baseMs = currentExpiry;
        newExpiration = new Date(baseMs + plan.days * 86400000).toISOString();
        Object.assign(user, {
          status: 'ativo',
          plan: 'premium',
          planId: localPayment.planId || 'mensal',
          planName: plan.name,
          subscriptionStatus: 'active',
          subscriptionStartedAt: user.subscriptionStartedAt || payment.date_approved || now,
          subscriptionUntil: newExpiration,
          expiresAt: newExpiration,
          lastPaymentId: paymentId,
          lastPaymentAmount: Number(payment.transaction_amount || localPayment.amount || plan.value),
          lastPaymentApprovedAt: payment.date_approved || now,
          paidAt: payment.date_approved || now,
          updatedAt: now
        });
        stored.accessGrantedAt = now;
        stored.subscriptionUntil = newExpiration;
        stored.daysGranted = plan.days;
        accessGranted = true;
      }
    }

    root.payments[paymentId] = stored;
    root.users[localPayment.userId] = user;
    root.paymentEvents = root.paymentEvents || {};
    root.paymentEvents[paymentId] = root.paymentEvents[paymentId] || {};
    const eventKey = String(Date.now()) + '_' + crypto.randomBytes(3).toString('hex');
    root.paymentEvents[paymentId][eventKey] = {
      status: remoteStatus,
      statusDetail: payment.status_detail || '',
      receivedAt: now,
      source: 'mercado_pago'
    };
    return root;
  });

  if (remoteStatus === 'approved' && accessGranted) {
    await awardReferralBonus(localPayment.userId, paymentId, now);
  }
  const updated = (await paymentRef.once('value')).val() || {};
  return { ...updated, accessGranted, subscriptionUntil: updated.subscriptionUntil || newExpiration };
}

app.get('/', (req, res) => {
  res.json({ online: true, service: 'Finance IA Pro Pix', version: '5.1.0', pixFix: 'v8.1-pix-persistente-exclusao-uid', timestamp: new Date().toISOString() });
});

app.get('/health', (req, res) => {
  res.json({
    success: true,
    version: '5.1.0',
    pixFix: 'v8.1-pix-persistente-exclusao-uid',
    firebase: true,
    mercadoPagoToken: Boolean(process.env.MERCADO_PAGO_ACCESS_TOKEN),
    webhookSecret: Boolean(process.env.MERCADO_PAGO_WEBHOOK_SECRET),
    deleteRoutes: true,
    timestamp: new Date().toISOString()
  });
});

app.post('/referral/visit', async (req, res) => {
  try {
    const code = normalizeReferralCode(req.body?.code);
    if (!code) return res.status(400).json({ error: 'Código de indicação inválido.' });
    const ownerUid = (await db.ref(`referralCodes/${code}`).once('value')).val();
    if (!ownerUid) return res.status(404).json({ error: 'Link de indicação não encontrado.' });
    await db.ref(`referralStats/${ownerUid}/clicks`).transaction(v => Number(v || 0) + 1);
    await db.ref(`referralStats/${ownerUid}`).update({ lastClickAt: new Date().toISOString() });
    res.json({ success: true });
  } catch (error) { console.error('referral visit:', error); res.status(500).json({ error: 'Não foi possível registrar o acesso.' }); }
});

app.post('/referral/setup', authenticate, async (req, res) => {
  try {
    const userRef = db.ref(`users/${req.user.uid}`);
    const profile = (await userRef.once('value')).val();
    if (!profile) return res.status(404).json({ error: 'Cadastro não encontrado.' });
    let code = normalizeReferralCode(profile.referralCode) || makeReferralCode(req.user.uid);
    const codeRef = db.ref(`referralCodes/${code}`);
    const currentOwner = (await codeRef.once('value')).val();
    if (currentOwner && currentOwner !== req.user.uid) code = `${code}${String(Date.now()).slice(-4)}`;
    const baseUrl = safeBaseUrl(req.body?.baseUrl);
    const updates = {};
    updates[`referralCodes/${code}`] = req.user.uid;
    updates[`users/${req.user.uid}/referralCode`] = code;
    updates[`users/${req.user.uid}/referralLink`] = `${baseUrl}?ref=${encodeURIComponent(code)}`;
    updates[`users/${req.user.uid}/updatedAt`] = new Date().toISOString();
    const incoming = normalizeReferralCode(req.body?.refCode);
    if (incoming && !profile.referredByUid) {
      const referrerUid = (await db.ref(`referralCodes/${incoming}`).once('value')).val();
      if (referrerUid && referrerUid !== req.user.uid) {
        const referrer = (await db.ref(`users/${referrerUid}`).once('value')).val() || {};
        updates[`users/${req.user.uid}/referredByUid`] = referrerUid;
        updates[`users/${req.user.uid}/referredByCode`] = incoming;
        updates[`users/${req.user.uid}/referredAt`] = new Date().toISOString();
        updates[`referrals/${referrerUid}/${req.user.uid}`] = {referredUid:req.user.uid,referredName:profile.name||'',referredEmail:profile.email||req.user.email||'',status:'registered',registeredAt:new Date().toISOString(),bonusAwarded:false};
        updates[`users/${referrerUid}/referralRegistrations`] = Number(referrer.referralRegistrations||0)+1;
      }
    }
    await db.ref().update(updates);
    const me = (await userRef.once('value')).val() || {};
    const referrals = (await db.ref(`referrals/${req.user.uid}`).once('value')).val() || {};
    const list = Object.values(referrals);
    const stats = (await db.ref(`referralStats/${req.user.uid}`).once('value')).val() || {};
    res.json({success:true,referralCode:me.referralCode,referralLink:me.referralLink,clicks:Number(stats.clicks||0),registrations:list.length,approvedPayments:list.filter(x=>x.bonusAwarded).length,daysEarned:Number(me.referralDaysEarned||0),pending:list.filter(x=>!x.bonusAwarded).length});
  } catch (error) { console.error('referral setup:', error); res.status(500).json({ error: 'Não foi possível configurar a indicação.' }); }
});

app.get('/referral/me', authenticate, async (req, res) => {
  try {
    const me = (await db.ref(`users/${req.user.uid}`).once('value')).val() || {};
    const referrals = (await db.ref(`referrals/${req.user.uid}`).once('value')).val() || {};
    const list = Object.values(referrals);
    const stats = (await db.ref(`referralStats/${req.user.uid}`).once('value')).val() || {};
    res.json({success:true,referralCode:me.referralCode||'',referralLink:me.referralLink||'',clicks:Number(stats.clicks||0),registrations:list.length,approvedPayments:list.filter(x=>x.bonusAwarded).length,daysEarned:Number(me.referralDaysEarned||0),pending:list.filter(x=>!x.bonusAwarded).length});
  } catch (error) { res.status(500).json({ error: 'Não foi possível carregar as indicações.' }); }
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
        description: `Finance IA Pro - ${plan.name}`,
        payment_method_id: 'pix',
        date_of_expiration: expiresAt,
        external_reference: externalReference,
        payer: {
          email,
          first_name: firstName,
          last_name: lastName,
          identification: { type: 'CPF', number: cpf }
        },
        notification_url: String(process.env.MERCADO_PAGO_WEBHOOK_URL || `${req.protocol}://${req.get('host')}/webhook`),
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
      paymentMethod: 'pix',
      paymentMethodId: 'pix',
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


app.post('/createCardPayment', authenticate, async (req, res) => {
  try {
    const planId = String(req.body.planId || '').trim();
    const plan = PLANS[planId];
    if (!plan) return res.status(400).json({ error: 'Plano inválido.' });
    const profile = (await db.ref(`users/${req.user.uid}`).once('value')).val();
    if (!profile) return res.status(404).json({ error: 'Cadastro do usuário não encontrado.' });
    const token = String(req.body.token || '').trim();
    const paymentMethodId = String(req.body.payment_method_id || req.body.paymentMethodId || '').trim();
    const issuerId = req.body.issuer_id || req.body.issuerId || undefined;
    const installments = Math.max(1, Number(req.body.installments || 1));
    const payerForm = req.body.payer || {};
    const requestedPaymentType = String(req.body.requestedPaymentType || 'credit_card').trim();
    const deviceSessionId = String(req.body.deviceSessionId || req.headers['x-meli-session-id'] || '').trim();
    const email = payerForm.email || profile.email || req.user.email || '';
    const cpf = onlyNumbers(payerForm.identification?.number || profile.cpf);
    const phone = onlyNumbers(profile.phone || profile.telefone || '');
    const { firstName, lastName } = splitName(profile.name || payerForm.first_name || payerForm.firstName || 'Cliente');
    if (!token || !paymentMethodId) return res.status(400).json({ error: 'Dados do cartão incompletos.' });
    if (!email) return res.status(400).json({ error: 'E-mail não cadastrado.' });
    if (cpf.length !== 11) return res.status(400).json({ error: 'CPF inválido.' });
    const externalReference = `${req.user.uid}|${planId}`;
    const payment = await mpRequest('/v1/payments', {
      method: 'POST',
      headers: {
        'X-Idempotency-Key': crypto.randomUUID(),
        ...(deviceSessionId ? { 'X-meli-session-id': deviceSessionId } : {})
      },
      body: JSON.stringify({
        transaction_amount: Number(plan.value),
        token,
        description: `Finance IA Pro - ${plan.name}`,
        installments,
        payment_method_id: paymentMethodId,
        ...(issuerId ? { issuer_id: issuerId } : {}),
        external_reference: externalReference,
        payer: {
          email,
          first_name: firstName,
          last_name: lastName,
          identification: { type: 'CPF', number: cpf },
          ...(phone.length >= 10 ? { phone: { area_code: phone.slice(0, 2), number: phone.slice(2) } } : {})
        },
        additional_info: {
          items: [{
            id: planId,
            title: `Finance IA Pro - ${plan.name}`,
            description: `${plan.days} dias de acesso ao aplicativo`,
            category_id: 'services',
            quantity: 1,
            unit_price: Number(plan.value)
          }],
          payer: {
            first_name: firstName,
            last_name: lastName,
            ...(phone.length >= 10 ? { phone: { area_code: phone.slice(0, 2), number: phone.slice(2) } } : {})
          }
        },
        metadata: { firebase_uid: req.user.uid, plan_id: planId, plan_name: plan.name, payment_method: requestedPaymentType, device_id_sent: Boolean(deviceSessionId) }
      })
    });
    const now = new Date().toISOString();
    const record = {
      userId: req.user.uid,
      userName: profile.name || '',
      userEmail: email,
      userCpfLast4: cpf.slice(-4),
      planId, planName: plan.name, amount: Number(plan.value),
      paymentMethod: payment.payment_type_id === 'debit_card' ? 'debit_card' : 'credit_card',
      requestedPaymentType,
      paymentTypeId: payment.payment_type_id || requestedPaymentType,
      paymentMethodId,
      installments: payment.payment_type_id === 'debit_card' ? 1 : installments,
      status: payment.status || 'pending',
      statusDetail: payment.status_detail || '',
      mercadoPagoId: String(payment.id),
      externalReference: payment.external_reference || externalReference,
      createdAt: now, updatedAt: now
    };
    await db.ref(`payments/${payment.id}`).set(record);
    await syncPayment(payment, record);
    const updated = (await db.ref(`payments/${payment.id}`).once('value')).val();
    res.status(201).json({ success: true, payment: { id: String(payment.id), ...updated } });
  } catch (error) {
    console.error('createCardPayment:', error);
    res.status(500).json({ error: error.message || 'Não foi possível processar o cartão.' });
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


async function expirePendingPaymentIfNeeded(paymentId, local) {
  const status = String(local?.status || '').toLowerCase();
  if (!['pending','in_process','authorized','unknown'].includes(status)) return local;
  const expiryMs = Date.parse(local?.expiresAt || local?.paymentExpiresAt || '');
  if (!Number.isFinite(expiryMs) || expiryMs > Date.now()) return local;

  let finalStatus = 'expired';
  try {
    const remote = await mpRequest(`/v1/payments/${encodeURIComponent(paymentId)}`);
    if (String(remote.status || '').toLowerCase() === 'approved') {
      await syncPayment(remote, local);
      return (await db.ref(`payments/${paymentId}`).once('value')).val() || local;
    }
    if (['pending','in_process','authorized'].includes(String(remote.status || '').toLowerCase())) {
      try {
        const cancelled = await mpRequest(`/v1/payments/${encodeURIComponent(paymentId)}`, {
          method: 'PUT',
          body: JSON.stringify({ status: 'cancelled' })
        });
        finalStatus = cancelled.status || 'cancelled';
      } catch (cancelError) {
        console.warn(`Não foi possível cancelar o Pix vencido ${paymentId}:`, cancelError.message);
      }
    } else {
      finalStatus = remote.status || 'expired';
    }
  } catch (error) {
    console.warn(`Falha ao consultar Pix vencido ${paymentId}:`, error.message);
  }
  const now = new Date().toISOString();
  await db.ref(`payments/${paymentId}`).update({ status: finalStatus, expiredAt: now, updatedAt: now });
  return (await db.ref(`payments/${paymentId}`).once('value')).val() || { ...local, status: finalStatus, expiredAt: now };
}

app.get('/latestPayment', authenticate, async (req, res) => {
  try {
    const snapshot = await db.ref('payments')
      .orderByChild('userId')
      .equalTo(req.user.uid)
      .once('value');

    const all = snapshot.val() || {};
    const entries = Object.entries(all).sort((a,b) =>
      Date.parse(b[1]?.createdAt || b[1]?.updatedAt || 0) - Date.parse(a[1]?.createdAt || a[1]?.updatedAt || 0)
    );
    if (!entries.length) return res.json({ success: true, payment: null });

    // Confere no Mercado Pago as cobranças ainda não finalizadas. Isso resolve
    // pagamentos feitos com o app aberto, em segundo plano ou fechado.
    for (const [id, originalLocal] of entries.slice(0, 10)) {
      const local = await expirePendingPaymentIfNeeded(id, originalLocal);
      if (['approved','rejected','cancelled','expired','refunded','charged_back'].includes(String(local.status || '').toLowerCase())) continue;
      try {
        const remote = await mpRequest(`/v1/payments/${encodeURIComponent(id)}`);
        await syncPayment(remote, local);
      } catch (syncError) {
        console.error(`Falha ao reconciliar pagamento ${id}:`, syncError.message);
      }
    }

    const refreshed = await db.ref('payments')
      .orderByChild('userId')
      .equalTo(req.user.uid)
      .once('value');
    const refreshedEntries = Object.entries(refreshed.val() || {}).sort((a,b) =>
      Date.parse(b[1]?.createdAt || b[1]?.updatedAt || 0) - Date.parse(a[1]?.createdAt || a[1]?.updatedAt || 0)
    );
    const [id, payment] = refreshedEntries[0] || [];
    res.json({ success: true, payment: id ? { id, ...payment } : null });
  } catch (error) {
    console.error('latestPayment:', error);
    res.status(500).json({ error: error.message || 'Não foi possível buscar o pagamento.' });
  }
 });

app.get('/myPayments', authenticate, async (req, res) => {
  try {
    const snapshot = await db.ref('payments').orderByChild('userId').equalTo(req.user.uid).once('value');
    const entries = Object.entries(snapshot.val() || {}).sort((a,b) =>
      Date.parse(b[1]?.createdAt || b[1]?.updatedAt || 0) - Date.parse(a[1]?.createdAt || a[1]?.updatedAt || 0)
    );
    const result = [];
    for (const [id, original] of entries.slice(0, 30)) {
      const current = await expirePendingPaymentIfNeeded(id, original);
      result.push({ id, ...current });
    }
    res.json({ success: true, payments: result });
  } catch (error) {
    console.error('myPayments:', error);
    res.status(500).json({ error: error.message || 'Não foi possível carregar os pagamentos.' });
  }
});

app.post('/reconcilePendingPayments' , authenticateAdmin, async (req, res) => {
  try {
    const snap = await db.ref('payments').once('value');
    const all = snap.val() || {};
    let checked = 0, approved = 0, failed = 0;
    for (const [id, local] of Object.entries(all)) {
      if (!['pending','in_process','authorized','unknown'].includes(String(local.status || '').toLowerCase())) continue;
      checked++;
      try {
        const remote = await mpRequest(`/v1/payments/${encodeURIComponent(id)}`);
        const result = await syncPayment(remote, local);
        if (String(remote.status).toLowerCase() === 'approved' && result.accessGrantedAt) approved++;
      } catch (error) {
        failed++;
        console.error(`Reconciliação ${id}:`, error.message);
      }
    }
    res.json({ success:true, checked, approved, failed, at:new Date().toISOString() });
  } catch (error) {
    res.status(500).json({ error:error.message || 'Falha na reconciliação.' });
  }
});


async function deleteUserCompletely(targetUid, context = {}) {
  const actorUid = String(context.actorUid || targetUid || '').trim();
  const source = String(context.source || 'self');
  if (!targetUid) throw new Error('UID do usuário não informado.');

  let authRecord = null;
  try { authRecord = await auth.getUser(targetUid); }
  catch (error) { if (error.code !== 'auth/user-not-found') throw error; }

  const targetProfile = (await db.ref(`users/${targetUid}`).once('value')).val() || {};
  const rootSnap = await db.ref().once('value');
  const root = rootSnap.val() || {};
  const email = String(targetProfile.email || authRecord?.email || '').trim().toLowerCase();
  const phone = onlyNumbers(targetProfile.phone || authRecord?.phoneNumber || '');

  // Descobre todos os CPFs associados ao UID, mesmo quando o perfil antigo não possui o campo cpf.
  const cpfCandidates = new Set();
  const addCpf = value => { const c = onlyNumbers(value); if (c.length === 11) cpfCandidates.add(c); };
  addCpf(targetProfile.cpf);
  addCpf(targetProfile.document);
  addCpf(targetProfile.documentNumber);

  const cpfIndexRoots = ['cpfIndex', 'cpfs', 'cpf', 'usersByCpf', 'usuariosPorCpf', 'cpfUsers', 'documentIndex'];
  for (const indexRoot of cpfIndexRoots) {
    for (const [key, value] of Object.entries(root[indexRoot] || {})) {
      const linkedUid = typeof value === 'object' && value
        ? String(value.uid || value.userId || value.id || value.value || '')
        : String(value || '');
      const linkedEmail = typeof value === 'object' && value ? String(value.email || '').trim().toLowerCase() : '';
      if (linkedUid === targetUid || (email && linkedEmail === email)) {
        addCpf(key);
        if (value && typeof value === 'object') {
          addCpf(value.cpf); addCpf(value.document); addCpf(value.documentNumber);
        }
      }
    }
  }

  const updates = {};
  const uidRoots = [
    'users','finance','userNotifications','deviceSessions','sessions','userSessions',
    'referrals','referralStats','referralCodesByUser','subscriptions','userSubscriptions',
    'profiles','userProfiles','preferences','userPreferences','alerts','userAlerts',
    'pushTokens','fcmTokens','devices','userDevices','activity','userActivity'
  ];
  uidRoots.forEach(path => { updates[`${path}/${targetUid}`] = null; });


  // Remove qualquer pasta criada diretamente com o UID, inclusive estruturas antigas não previstas.
  for (const [topKey, topValue] of Object.entries(root)) {
    if (!topValue || typeof topValue !== 'object' || Array.isArray(topValue)) continue;
    if (Object.prototype.hasOwnProperty.call(topValue, targetUid)) updates[`${topKey}/${targetUid}`] = null;
    for (const [childKey, childValue] of Object.entries(topValue)) {
      if (!childValue || typeof childValue !== 'object' || Array.isArray(childValue)) continue;
      const linkedUid = String(childValue.userId || childValue.uid || childValue.ownerUid || childValue.firebaseUid || '');
      if (linkedUid === targetUid) updates[`${topKey}/${childKey}`] = null;
    }
  }

  // Remove índices de CPF em todos os formatos e qualquer entrada ligada ao UID/e-mail.
  for (const indexRoot of cpfIndexRoots) {
    for (const cpf of cpfCandidates) {
      const formatted = `${cpf.slice(0,3)}.${cpf.slice(3,6)}.${cpf.slice(6,9)}-${cpf.slice(9)}`;
      updates[`${indexRoot}/${cpf}`] = null;
      updates[`${indexRoot}/${formatted}`] = null;
    }
    for (const [key, value] of Object.entries(root[indexRoot] || {})) {
      const linkedUid = typeof value === 'object' && value
        ? String(value.uid || value.userId || value.id || value.value || '')
        : String(value || '');
      const linkedEmail = typeof value === 'object' && value ? String(value.email || '').trim().toLowerCase() : '';
      const linkedCpf = typeof value === 'object' && value ? onlyNumbers(value.cpf || value.document || value.documentNumber) : '';
      if (linkedUid === targetUid || (email && linkedEmail === email) || (linkedCpf && cpfCandidates.has(linkedCpf)) || cpfCandidates.has(onlyNumbers(key))) {
        updates[`${indexRoot}/${key}`] = null;
      }
    }
  }

  const simpleIndexes = ['phoneIndex','emailIndex','usersByEmail','usuariosPorEmail','userEmailIndex'];
  for (const indexRoot of simpleIndexes) {
    for (const [key, value] of Object.entries(root[indexRoot] || {})) {
      const linkedUid = typeof value === 'object' && value
        ? String(value.uid || value.userId || value.id || value.value || '')
        : String(value || '');
      const linkedEmail = typeof value === 'object' && value ? String(value.email || '').trim().toLowerCase() : '';
      if (linkedUid === targetUid || (email && (linkedEmail === email || String(key).trim().toLowerCase() === email)) || (phone && onlyNumbers(key) === phone)) {
        updates[`${indexRoot}/${key}`] = null;
      }
    }
  }
  if (phone) updates[`phoneIndex/${phone}`] = null;
  if (email) {
    updates[`emailIndex/${email.replace(/[.#$\[\]/]/g, '_')}`] = null;
    updates[`usersByEmail/${email.replace(/[.#$\[\]/]/g, '_')}`] = null;
  }

  // Remove pagamentos, eventos e referências associados ao usuário.
  const paymentIds = [];
  for (const [paymentId, payment] of Object.entries(root.payments || {})) {
    if (String(payment?.userId || payment?.uid || '') === targetUid || (email && String(payment?.payerEmail || payment?.email || '').toLowerCase() === email)) {
      paymentIds.push(paymentId);
      updates[`payments/${paymentId}`] = null;
      updates[`paymentEvents/${paymentId}`] = null;
    }
  }
  for (const [ownerUid, referrals] of Object.entries(root.referrals || {})) {
    if (referrals && Object.prototype.hasOwnProperty.call(referrals, targetUid)) updates[`referrals/${ownerUid}/${targetUid}`] = null;
  }

  // Guarda somente auditoria técnica, sem CPF, telefone ou e-mail em texto puro.
  const auditKey = db.ref('deletionAudits').push().key;
  updates[`deletionAudits/${auditKey}`] = {
    targetUid,
    actorUid,
    source,
    cpfCount: cpfCandidates.size,
    paymentCount: paymentIds.length,
    authenticationExisted: Boolean(authRecord),
    createdAt: new Date().toISOString()
  };

  await db.ref().update(updates);

  let authenticationDeleted = false;
  try {
    await auth.deleteUser(targetUid);
    authenticationDeleted = true;
  } catch (error) {
    if (error.code !== 'auth/user-not-found') throw error;
  }

  return {
    uid: targetUid,
    cpfRemoved: cpfCandidates.size > 0,
    cpfEntriesRemoved: cpfCandidates.size,
    paymentsRemoved: paymentIds.length,
    phoneRemoved: Boolean(phone),
    authenticationDeleted
  };
}

async function adminDeleteUserHandler(req, res) {
  try {
    const targetUid = String(req.body?.uid || req.body?.targetUid || req.body?.userId || req.query?.uid || '').trim();
    if (!targetUid) return res.status(400).json({ error: 'UID do usuário não informado.' });
    if (targetUid === req.user.uid) return res.status(400).json({ error: 'Use a opção Excluir minha conta para apagar sua própria conta.' });

    const targetProfile = (await db.ref(`users/${targetUid}`).once('value')).val() || {};
    const targetEmail = String(targetProfile.email || '').toLowerCase();
    if (['owner', 'admin'].includes(String(targetProfile.role || '').toLowerCase()) || OWNER_EMAILS.includes(targetEmail)) {
      return res.status(403).json({ error: 'Contas administrativas não podem ser excluídas por esta tela.' });
    }

    const result = await deleteUserCompletely(targetUid, { actorUid: req.user.uid, source: 'admin' });
    return res.json({ success: true, message: 'Conta e todos os dados foram excluídos.', ...result });
  } catch (error) {
    console.error('admin/deleteUser:', error);
    return res.status(500).json({ error: error.message || 'Não foi possível excluir completamente o usuário.' });
  }
}

const adminDeleteRoutes = [
  '/admin/deleteUser','/admin/delete-user','/admin/users/delete','/admin/users/delete-complete',
  '/api/admin/deleteUser','/api/admin/delete-user','/api/admin/users/delete','/deleteUser','/delete-user-complete'
];
for (const route of adminDeleteRoutes) {
  app.post(route, authenticateAdmin, adminDeleteUserHandler);
  app.delete(route, authenticateAdmin, adminDeleteUserHandler);
}

async function selfDeleteUserHandler(req, res) {
  try {
    const profile = (await db.ref(`users/${req.user.uid}`).once('value')).val() || {};
    const profileEmail = String(profile.email || req.user.email || '').toLowerCase();
    if (['owner', 'admin'].includes(String(profile.role || '').toLowerCase()) || OWNER_EMAILS.includes(profileEmail)) {
      return res.status(403).json({ error: 'A conta do proprietário ou administrador não pode ser excluída por esta opção.' });
    }
    const result = await deleteUserCompletely(req.user.uid, { actorUid: req.user.uid, source: 'self' });
    return res.json({ success: true, message: 'Sua conta e todos os dados foram excluídos.', ...result });
  } catch (error) {
    console.error('account/delete:', error);
    return res.status(500).json({ error: error.message || 'Não foi possível excluir completamente sua conta.' });
  }
}

const selfDeleteRoutes = [
  '/account/delete','/account/delete-complete','/account/deleteUser','/api/account/delete',
  '/api/account/delete-complete','/deleteAccount','/delete-my-account'
];
for (const route of selfDeleteRoutes) {
  app.post(route, authenticate, selfDeleteUserHandler);
  app.delete(route, authenticate, selfDeleteUserHandler);
}

app.post('/admin/cancelPayment', authenticateAdmin, async (req, res) => {
  try {
    const paymentId = String(req.body.paymentId || '').trim();
    if (!paymentId) return res.status(400).json({ error: 'ID do pagamento não informado.' });

    const ref = db.ref(`payments/${paymentId}`);
    const local = (await ref.once('value')).val();
    if (!local) return res.status(404).json({ error: 'Pagamento não encontrado no Firebase.' });

    let current = await mpRequest(`/v1/payments/${encodeURIComponent(paymentId)}`);
    const now = new Date().toISOString();
    const amount = Number(current.transaction_amount || local.amount || 0);
    const refundedAmount = Number(current.transaction_details?.total_refunded_amount || 0);

    // Se o Mercado Pago já concluiu a reversão, apenas sincroniza o painel.
    if (current.status === 'refunded' || (amount > 0 && refundedAmount >= amount)) {
      await ref.update({status:'refunded', adminAction:'refund', adminActionBy:req.user.uid, adminActionAt:now, updatedAt:now});
      return res.json({success:true, action:'refund', status:'refunded', alreadyDone:true, message:'Pagamento já estava reembolsado e foi sincronizado.'});
    }
    if (current.status === 'cancelled') {
      await ref.update({status:'cancelled', adminAction:'cancel', adminActionBy:req.user.uid, adminActionAt:now, updatedAt:now});
      return res.json({success:true, action:'cancel', status:'cancelled', alreadyDone:true, message:'Pagamento já estava cancelado e foi sincronizado.'});
    }

    let action, finalStatus, refundId='';
    if (current.status === 'approved') {
      action = 'refund';
      try {
        const refund = await mpRequest(`/v1/payments/${encodeURIComponent(paymentId)}/refunds`, {
          method: 'POST',
          headers: { 'X-Idempotency-Key': `refund-${paymentId}` },
          body: JSON.stringify({})
        });
        refundId = refund?.id ? String(refund.id) : '';
      } catch (refundError) {
        // A devolução pode ter sido processada antes de a resposta chegar. Confere novamente.
        current = await mpRequest(`/v1/payments/${encodeURIComponent(paymentId)}`);
        const total = Number(current.transaction_details?.total_refunded_amount || 0);
        if (!(current.status === 'refunded' || (amount > 0 && total >= amount))) throw refundError;
      }
      current = await mpRequest(`/v1/payments/${encodeURIComponent(paymentId)}`);
      finalStatus = current.status === 'refunded' || Number(current.transaction_details?.total_refunded_amount || 0) >= amount ? 'refunded' : 'refunded';

      const userRef = db.ref(`users/${local.userId}`);
      const user = (await userRef.once('value')).val() || {};
      if (String(user.lastPaymentId || '') === paymentId) {
        await userRef.update({status:'bloqueado', expiresAt:now, paymentReversedAt:now, updatedAt:now}).catch(err=>console.error('Falha ao bloquear acesso após reembolso:',err));
      }
    } else if (['pending', 'in_process', 'authorized'].includes(current.status)) {
      action = 'cancel';
      const cancelled = await mpRequest(`/v1/payments/${encodeURIComponent(paymentId)}`, {
        method: 'PUT',
        body: JSON.stringify({ status: 'cancelled' })
      });
      finalStatus = cancelled.status || 'cancelled';
    } else if (current.status === 'charged_back') {
      finalStatus = 'charged_back'; action = 'refund';
    } else {
      return res.status(409).json({ error: `Não é possível cancelar um pagamento com status ${current.status}.` });
    }

    await ref.update({
      status: finalStatus,
      statusDetail: current.status_detail || local.statusDetail || '',
      adminAction: action,
      adminActionBy: req.user.uid,
      adminActionAt: now,
      refundId,
      updatedAt: now
    });

    return res.json({success:true, action, status:finalStatus, message:action==='refund'?'Reembolso realizado e painel atualizado.':'Pagamento cancelado e painel atualizado.'});
  } catch (error) {
    console.error('admin/cancelPayment:', error);
    return res.status(500).json({ error: error.message || 'Não foi possível cancelar ou reembolsar o pagamento.' });
  }
});

async function processMercadoPagoWebhook(req, res) {
  const paymentId = paymentIdFromRequest(req);
  try {
    if (!paymentId) return res.status(200).json({ received: true, ignored: 'sem_payment_id' });
    if (!validateWebhookSignature(req, paymentId)) return res.status(401).json({ received: false, error: 'assinatura_invalida' });

    const payment = await mpRequest(`/v1/payments/${encodeURIComponent(paymentId)}`);
    const local = (await db.ref(`payments/${paymentId}`).once('value')).val();
    const result = await syncPayment(payment, local);
    console.log(`Pagamento ${paymentId} sincronizado: ${payment.status}; acesso=${Boolean(result.accessGrantedAt)}`);
    return res.status(200).json({ received: true, paymentId, status: payment.status });
  } catch (error) {
    console.error('webhook:', error);
    // Retorna erro para o Mercado Pago tentar entregar novamente.
    return res.status(500).json({ received: false, error: 'falha_ao_processar' });
  }
}

app.post('/webhook', processMercadoPagoWebhook);
app.get('/webhook', processMercadoPagoWebhook);

app.use((req, res) => res.status(404).json({ error: 'Rota não encontrada.' }));


async function reconcileRecentPendingPayments() {
  try {
    const snap = await db.ref('payments').once('value');
    const all = snap.val() || {};
    const cutoff = Date.now() - 48 * 60 * 60 * 1000;
    for (const [id, local] of Object.entries(all)) {
      const status = String(local.status || '').toLowerCase();
      const created = Date.parse(local.createdAt || local.updatedAt || 0);
      if (!['pending','in_process','authorized','unknown'].includes(status) || (created && created < cutoff)) continue;
      try {
        const remote = await mpRequest(`/v1/payments/${encodeURIComponent(id)}`);
        await syncPayment(remote, local);
      } catch (error) {
        console.error(`Reconciliação automática ${id}:`, error.message);
      }
    }
  } catch (error) {
    console.error('Reconciliação automática:', error.message);
  }
}
setInterval(reconcileRecentPendingPayments, 2 * 60 * 1000).unref();
setTimeout(reconcileRecentPendingPayments, 15000).unref();

const PORT = Number(process.env.PORT || 10000);
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Finance IA Pro Pix online na porta ${PORT}`);
});
