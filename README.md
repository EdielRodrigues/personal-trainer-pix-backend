# Backend Pix — Personal Trainer

Arquivos para subir em um repositório do GitHub e conectar ao Render.

## Arquivos que devem ir para o GitHub

- `index.js`
- `package.json`
- `render.yaml`
- `.env.example` apenas como modelo; ele não contém as chaves reais.

## Criar o serviço no Render

1. Crie um repositório novo no GitHub.
2. Envie os arquivos deste pacote para a raiz do repositório.
3. No Render, escolha **New Web Service**.
4. Conecte o repositório.
5. Build Command: `npm install`
6. Start Command: `npm start`

## Variáveis no Render

Cadastre em **Environment**:

- `MERCADO_PAGO_ACCESS_TOKEN`
- `FIREBASE_DATABASE_URL`
- `FIREBASE_SERVICE_ACCOUNT_JSON`
- `MERCADO_PAGO_WEBHOOK_SECRET` depois de criar o webhook.

Não envie o Access Token nem a conta de serviço para o GitHub.

## URLs

Depois do deploy, abra:

- `https://SEU-SERVICO.onrender.com/`
- `https://SEU-SERVICO.onrender.com/health`

No aplicativo do cliente, coloque em `firebase-config.js`:

```js
functionsBaseUrl: "https://SEU-SERVICO.onrender.com"
```

No Mercado Pago, configure o webhook:

```text
https://SEU-SERVICO.onrender.com/webhook
```

Selecione notificações de pagamentos.
