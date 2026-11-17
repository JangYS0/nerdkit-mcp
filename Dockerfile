FROM node:20-alpine
WORKDIR /app
COPY package.json server.mjs ./
ENTRYPOINT ["node", "server.mjs"]
