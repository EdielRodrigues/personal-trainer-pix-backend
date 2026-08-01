# Backend Finance IA Pro v8.1.2

Correção do deploy no Render para o erro `Cannot find module @firebase/app`.

- firebase-admin fixado em 12.7.0
- @firebase/app incluído explicitamente
- usa exatamente as variáveis já existentes no Render

Build: `yarn install` ou `npm install`
Start: `node index.js` ou `npm start`

Faça **Clear build cache & deploy**.
