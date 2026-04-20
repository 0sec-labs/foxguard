# Safe Dockerfile — no TLS-disabling env vars
FROM node:20-alpine

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=8080

COPY package.json ./
RUN npm install --omit=dev

COPY . .

CMD ["node", "server.js"]
