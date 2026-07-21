'use strict';

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const admin = require('firebase-admin');

const app = express();

/* =========================================================
   CONFIGURAÇÕES BÁSICAS
========================================================= */

app.use(
  cors({
    origin: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-Id', 'X-Signature']
  })
);

app.use(express.json({ limit: '1mb' }));

/* =========================================================
   FIREBASE ADMIN
========================================================= */

function initializeFirebase() {
  const serviceAccountJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  const databaseURL = process.env.FIREBASE_DATABASE_URL;

  if (!serviceAccountJson) {
    throw new Error(
      'FIREBASE_SERVICE_ACCOUNT_JSON não foi configurado no Render.'
    );
  }

  if (!databaseURL) {
    throw new Error(
      'FIREBASE_DATABASE_URL não foi configurado no Render.'
    );
  }

  let serviceAccount;

  try {
    serviceAccount = JSON.parse(serviceAccountJson);
  } catch (error) {
    throw new Error(
      'FIREBASE_SERVICE_ACCOUNT_JSON está inválido. Cole o JSON completo da conta de serviço.'
    );
  }

  if (serviceAccount.private_key) {
    serviceAccount.private_key = serviceAccount.private_key.replace(
      /\\n/g,
      '\n'
    );
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

/* =========================================================
   PLANOS
========================================================= */

const PLANS = {
  mensal: {
    name: 'Plano Mensal',
    value: 19.9,
    days: 30
  },

  trimestral: {
    name: 'Plano Trimestral',
    value: 49.9,
    days: 90
  },

  anual: {
    name: 'Plano Anual',
    value: 149.9,
    days: 365
  },

  vitalicio: {
    name: 'Acesso Vitalício',
    value: 299.9,
    days: 36500
  }
};

/* =========================================================
   FUNÇÕES AUXILIARES
========================================================= */

function getMercadoPagoToken() {
  const token = process.env.MERCADO_PAGO_ACCESS_TOKEN;

if (!token) {
    throw new Error(
      'MERCADO_PAGO_ACCESS_TOKEN não configurado no servidor.'
    );
  }

  return token;
}

function getWebhookSecret() {
  return process.env.MERCADO_PAGO_WEBHOOK_SECRET || '';
}

function onlyNumbers(value) {
  return String(value || '').replace(/\D/g, '');
}

function getFirstName(fullName) {
  const parts = String(fullName || 'Cliente')
    .trim()
    .split(/\s+/)
    .filter(Boolean);

  return parts[0] || 'Cliente';
}

function getLastName(fullName) {
  const parts = String(fullName || '')
    .trim()
    .split(/\s+/)
    .filter(Boolean);

  if (parts.length <= 1) {
    return 'Cliente';
  }

  return parts.slice(1).join(' ');
}

function getPaymentId(req) {
  return String(
    req.query['data.id'] ||
      req.query.id ||
      req.body?.data?.id ||
      req.body?.id ||
      ''
  ).trim();
}

/* =========================================================
   CHAMADAS PARA O MERCADO PAGO
========================================================= */

async function mercadoPagoRequest(path, options = {}) {
  const token = getMercadoPagoToken();

  const response = await fetch(
    `https://api.mercadopago.com${path}`,
    {
      ...options,
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        Accept: 'application/json',
        ...(options.headers || {})
      }
    }
  );

  let result;

  try {
    result = await response.json();
  } catch (error) {
    result = {};
  }

  if (!response.ok) {
    console.error('Erro Mercado Pago:', {
      status: response.status,
      result
    });

    throw new Error(
      result.message ||
        result.error ||
        `Erro no Mercado Pago. Status ${response.status}.`
    );
  }

  return result;
}


/* =========================================================
   AUTENTICAÇÃO FIREBASE
========================================================= */

async function authenticate(req, res, next) {
  try {
    const authorization = req.headers.authorization || '';

    if (!authorization.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'Não autenticado. Token não informado.'
      });
    }

    const idToken = authorization.slice(7).trim();

    if (!idToken) {
      return res.status(401).json({
        error: 'Token inválido.'
      });
    }

    req.user = await admin.auth().verifyIdToken(idToken);

    return next();
  } catch (error) {
    console.error('Erro de autenticação:', error.message);

    return res.status(401).json({
      error: 'Sessão inválida ou expirada.'
    });
  }
}

/* =========================================================
   VALIDAÇÃO DA ASSINATURA DO WEBHOOK
========================================================= */

function validateWebhookSignature(req, dataId) {
  const secret = getWebhookSecret();

  /*
   * Enquanto a chave ainda não foi adicionada no Render,
   * o webhook continua funcionando, mas mostra aviso no log.
   */
  if (!secret) {
    console.warn(
      'MERCADO_PAGO_WEBHOOK_SECRET ainda não configurado. Assinatura não validada.'
    );

    return true;
  }

  const xSignature = String(req.headers['x-signature'] || '');
  const xRequestId = String(req.headers['x-request-id'] || '');

  if (!xSignature || !xRequestId || !dataId) {
    return false;
  }

  const parts = xSignature.split(',');

  let timestamp = '';
  let receivedHash = '';

  for (const part of parts) {
    const [key, value] = part.trim().split('=');

    if (key === 'ts') {
      timestamp = value;
    }

    if (key === 'v1') {
      receivedHash = value;
    }
  }

  if (!timestamp || !receivedHash) {
    return false;
  }

  const manifest = `id:${dataId};request-id:${xRequestId};ts:${timestamp};`;

  const calculatedHash = crypto
    .createHmac('sha256', secret)
    .update(manifest)
    .digest('hex');

  const receivedBuffer = Buffer.from(receivedHash, 'utf8');
  const calculatedBuffer = Buffer.from(calculatedHash, 'utf8');

  if (receivedBuffer.length !== calculatedBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(
    receivedBuffer,
    calculatedBuffer
  );
}
/* =========================================================
   SINCRONIZAR PAGAMENTO E LIBERAR USUÁRIO
========================================================= */

async function syncPayment(payment, localPayment) {
  const paymentId = String(payment.id);

  const updates = {
    status: payment.status || 'unknown',
    statusDetail: payment.status_detail || '',
    updatedAt: new Date().toISOString()
  };

  if (
    payment.status === 'approved' &&
    localPayment.status !== 'approved'
  ) {
    const plan = PLANS[localPayment.planId];

    if (!plan) {
      throw new Error(
        `Plano ${localPayment.planId} não encontrado.`
      );
    }

    const userRef = db.ref(`users/${localPayment.userId}`);
    const userSnapshot = await userRef.once('value');
    const userData = userSnapshot.val() || {};

    let baseDate = new Date();

    if (userData.expiresAt) {
      const currentExpiration = new Date(userData.expiresAt);

      if (
        !Number.isNaN(currentExpiration.getTime()) &&
        currentExpiration > new Date()
      ) {
        baseDate = currentExpiration;
      }
    }

    const expirationDate = new Date(
      baseDate.getTime() + plan.days * 86400000
    );

    updates.approvedAt = new Date().toISOString();

    await userRef.update({
      status: 'ativo',
      plan: localPayment.planId,
      planName: plan.name,
      expiresAt: expirationDate.toISOString(),
      lastPaymentId: paymentId,
      updatedAt: new Date().toISOString()
    });
  }

  await db.ref(`payments/${paymentId}`).update(updates);

  return updates;
}

/* =========================================================
   ROTA PRINCIPAL
========================================================= */

app.get('/', (req, res) => {
  return res.status(200).json({
    online: true,
    service: 'Personal Trainer Pix',
    message: 'Backend funcionando corretamente.',
    timestamp: new Date().toISOString()
  });
});

/* =========================================================
   VERIFICAÇÃO DE SAÚDE
========================================================= */

app.get('/health', (req, res) => {
  return res.status(200).json({
    success: true,
    firebase: true,
    mercadoPagoToken: Boolean(
      process.env.MERCADO_PAGO_ACCESS_TOKEN
    ),
    webhookSecret: Boolean(
      process.env.MERCADO_PAGO_WEBHOOK_SECRET
    ),
    timestamp: new Date().toISOString()
  });
});

/* =========================================================
   CRIAR PIX
========================================================= */

app.post('/createPix', authenticate, async (req, res) => {
  try {
    const planId = String(req.body.planId || '').trim();
    const plan = PLANS[planId];

    if (!plan) {
      return res.status(400).json({
        error: 'Plano inválido.'
      });
    }

    const userSnapshot = await db
      .ref(`users/${req.user.uid}`)
      .once('value');

    const profile = userSnapshot.val();

    if (!profile) {
      return res.status(404).json({
        error: 'Cadastro do usuário não encontrado.'
      });
    }

    const payerEmail =
      profile.email || req.user.email || '';

    if (!payerEmail) {
      return res.status(400).json({
        error: 'O usuário não possui e-mail cadastrado.'
      });
    }

    const cpf = onlyNumbers(profile.cpf);

    if (cpf.length !== 11) {
      return res.status(400).json({
        error: 'CPF inválido ou não cadastrado.'
      });
    }

    const idempotencyKey = crypto.randomUUID();

    const expiresAt = new Date(
      Date.now() + 30 * 60 * 1000
    ).toISOString();

    const paymentBody = {
      transaction_amount: Number(plan.value),
      description:
        `Personal Trainer Avançado Pro - ${plan.name}`,
      payment_method_id: 'pix',
      date_of_expiration: expiresAt,
      external_reference: `${req.user.uid}|${planId}`,
      payer: {
        email: payerEmail,
        first_name: getFirstName(profile.name),
        last_name: getLastName(profile.name),
        identification: {
          type: 'CPF',
          number: cpf
        }
      },
      metadata: {
        firebase_uid: req.user.uid,
        plan_id: planId,
        plan_name: plan.name
      }
    };

    const payment = await mercadoPagoRequest(
      '/v1/payments',
      {
        method: 'POST',
        headers: {
          'X-Idempotency-Key': idempotencyKey
        },
        body: JSON.stringify(paymentBody)
      }
    );

    const transactionData =
      payment.point_of_interaction?.transaction_data || {};

    const localPayment = {
      userId: req.user.uid,
      userName: profile.name || '',
      userEmail: payerEmail,
      userCpfLast4: cpf.slice(-4),

      planId,
      planName: plan.name,
      amount: Number(plan.value),

      status: payment.status || 'pending',
      statusDetail: payment.status_detail || '',

      mercadoPagoId: String(payment.id),

      qrCode: transactionData.qr_code || '',
      qrCodeBase64:
        transactionData.qr_code_base64 || '',
      ticketUrl: transactionData.ticket_url || '',

      externalReference:
        payment.external_reference ||
        `${req.user.uid}|${planId}`,

      createdAt: new Date().toISOString(),
      expiresAt,
      updatedAt: new Date().toISOString()
    };

    await db
      .ref(`payments/${payment.id}`)
      .set(localPayment);

    return res.status(201).json({
      success: true,
      payment: {
        id: String(payment.id),
        ...localPayment
      }
    });
  } catch (error) {
    console.error('Erro ao criar Pix:', error);

    return res.status(500).json({
      error:
        error.message ||
        'Não foi possível gerar o Pix.'
    });
  }
});

/* =========================================================
   CONSULTAR PAGAMENTO
========================================================= */

app.get(
  '/paymentStatus',
  authenticate,
  async (req, res) => {
    try {
      const paymentId = String(req.query.id || '').trim();

      if (!paymentId) {
        return res.status(400).json({
          error: 'ID do pagamento não informado.'
        });
      }

      const paymentSnapshot = await db
        .ref(`payments/${paymentId}`)
        .once('value');

      const localPayment = paymentSnapshot.val();

      if (
        !localPayment ||
        localPayment.userId !== req.user.uid
      ) {
        return res.status(404).json({
          error: 'Pagamento não encontrado.'
        });
      }

      const payment = await mercadoPagoRequest(
        `/v1/payments/${encodeURIComponent(paymentId)}`
      );

      const updates = await syncPayment(
        payment,
        localPayment
      );

      const updatedSnapshot = await db
        .ref(`payments/${paymentId}`)
        .once('value');

      return res.status(200).json({
        success: true,
        payment: {
          id: paymentId,
          ...updatedSnapshot.val(),
          ...updates
        }
      });
    } catch (error) {
      console.error(
        'Erro ao consultar pagamento:',
        error
      );

      return res.status(500).json({
        error:
          error.message ||
          'Não foi possível consultar o pagamento.'
      });
    }
  }
);
/* =========================================================
   ÚLTIMO PAGAMENTO DO USUÁRIO
========================================================= */

app.get(
  '/latestPayment',
  authenticate,
  async (req, res) => {
    try {
      const snapshot = await db
        .ref('payments')
        .orderByChild('userId')
        .equalTo(req.user.uid)
        .limitToLast(1)
        .once('value');

      const payments = snapshot.val() || {};
      const ids = Object.keys(payments);

      if (!ids.length) {
        return res.status(200).json({
          success: true,
          payment: null
        });
      }

      const paymentId = ids[0];

      return res.status(200).json({
        success: true,
        payment: {
          id: paymentId,
          ...payments[paymentId]
        }
      });
    } catch (error) {
      console.error(
        'Erro ao buscar último pagamento:',
        error
      );

      return res.status(500).json({
        error:
          error.message ||
          'Não foi possível buscar o pagamento.'
      });
    }
  }
);

/* =========================================================
   WEBHOOK MERCADO PAGO
========================================================= */

app.post('/webhook', async (req, res) => {
  const paymentId = getPaymentId(req);

  try {
    if (!paymentId) {
      console.log(
        'Webhook recebido sem ID de pagamento:',
        req.body
      );

      return res.sendStatus(200);
    }

    const validSignature = validateWebhookSignature(
      req,
      paymentId
    );

    if (!validSignature) {
      console.warn(
        'Webhook recusado: assinatura inválida.',
        {
          paymentId,
          requestId: req.headers['x-request-id']
        }
      );

      return res.sendStatus(401);
    }

    /*
     * Responde rapidamente para o Mercado Pago.
     * O processamento continua logo em seguida.
     */
    res.sendStatus(200);

    const payment = await mercadoPagoRequest(
      `/v1/payments/${encodeURIComponent(paymentId)}`
    );

    const localSnapshot = await db
      .ref(`payments/${paymentId}`)
      .once('value');

    const localPayment = localSnapshot.val();

    if (!localPayment) {
      console.warn(
        `Pagamento ${paymentId} não foi encontrado no Firebase.`
      );

      return;
    }

    await syncPayment(payment, localPayment);

    console.log(
      `Pagamento ${paymentId} sincronizado. Status: ${payment.status}`
    );
  } catch (error) {
    console.error('Erro no webhook:', error);
  }
});

/* =========================================================
   ROTA NÃO ENCONTRADA
========================================================= */

app.use((req, res) => {
  return res.status(404).json({
    error: 'Rota não encontrada.'
  });
});

/* =========================================================
   TRATAMENTO DE ERROS
========================================================= */

app.use((error, req, res, next) => {
  console.error('Erro interno:', error);

  if (res.headersSent) {
    return next(error);
  }

  return res.status(500).json({
    error: 'Erro interno do servidor.'
  });
});

/* =========================================================
   INICIAR SERVIDOR NO RENDER
========================================================= */

const PORT = Number(process.env.PORT || 10000);

app.listen(PORT, '0.0.0.0', () => {
  console.log('======================================');
  console.log('Personal Trainer Pix iniciado');
  console.log(`Porta: ${PORT}`);
  console.log(
    `Mercado Pago: ${
      process.env.MERCADO_PAGO_ACCESS_TOKEN
        ? 'configurado'
        : 'não configurado'
    }`
  );
  console.log(
    `Webhook Secret: ${
      process.env.MERCADO_PAGO_WEBHOOK_SECRET
        ? 'configurado'
        : 'ainda não configurado'
    }`
  );
  console.log('======================================');
});


