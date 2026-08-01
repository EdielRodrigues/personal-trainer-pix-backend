FINANCE IA PRO BACKEND v8.0.1

Correção do deploy no Render:
- removido uso da API antiga por namespace do firebase-admin;
- usado Firebase Admin modular;
- firebase-admin fixado na versão 14.2.0;
- compatível com Node.js 22.

No Render:
Build Command: npm install
Start Command: npm start

Após publicar, abra /health e confirme version 5.0.1.
Recomendado: Manual Deploy > Clear build cache & deploy.
