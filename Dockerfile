# Works on Railway, Fly.io, Koyeb or any container host.
FROM node:22-alpine
WORKDIR /app
COPY package*.json build.mjs ./
COPY client ./client
COPY shared ./shared
COPY docs/diagrams ./docs/diagrams
RUN npm ci
COPY . .
RUN node build.mjs
ENV NODE_ENV=production PORT=3000 DB_PATH=/app/data/commitrps.db
EXPOSE 3000
RUN mkdir -p /app/data && chown -R node:node /app
USER node
CMD ["node", "server/index.js"]
