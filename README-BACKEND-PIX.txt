BACKEND PIX — CONFIGURAÇÃO SEGURA

1. Nunca coloque o Access Token no HTML, firebase-config.js ou GitHub público.
2. Configure um projeto Firebase com Authentication e Realtime Database.
3. Instale Firebase CLI e faça login.
4. Dentro desta pasta: npm install
5. Configure o segredo MERCADO_PAGO_ACCESS_TOKEN no ambiente das Cloud Functions.
6. Publique a função e copie a URL terminada em /api para functionsBaseUrl nos dois firebase-config.js.
7. No Mercado Pago, configure o webhook para: SUA_URL/api/webhook
8. Primeiro use credenciais de teste; só depois troque para produção.

Rotas:
POST /api/createPix
GET /api/paymentStatus?id=...
GET /api/latestPayment
POST /api/webhook
