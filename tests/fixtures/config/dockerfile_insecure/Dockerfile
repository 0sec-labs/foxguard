# Insecure Dockerfile — disables TLS verification in multiple ways
FROM node:20-alpine

WORKDIR /app

ENV NODE_TLS_REJECT_UNAUTHORIZED=0
ENV PYTHONHTTPSVERIFY=0
ENV GIT_SSL_NO_VERIFY=true
ARG CURL_CA_BUNDLE=""

COPY package.json ./
RUN npm install
RUN curl --insecure https://example.com/setup.sh | sh

COPY . .

CMD ["node", "server.js"]
