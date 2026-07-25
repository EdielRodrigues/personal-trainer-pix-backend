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

async function authenticateAdmin(req, res, next) {
  return authenticate(req, res, async () => {
    try {
      const profile = (await db.ref(`users/${req.user.uid}`).once('value')).val();
      if (profile?.role !== 'admin') return res.status(403).json({ error: 'Acesso permitido somente para administrador.' });
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
    await awardReferralBonus(localPayment.userId, paymentId, now);
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
      paymentMethod: 'pix',
      paymentMethodId: 'pix',
      status: payment.status || 'pending',
      statusDetail: payment.status_detail || '',
      deviceIdSent: Boolean(deviceSessionId),
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
        description: `Personal Trainer Avançado Pro - ${plan.name}`,
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
            title: `Personal Trainer Avançado Pro - ${plan.name}`,
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
