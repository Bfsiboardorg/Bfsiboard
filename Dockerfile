FROM node:20-alpine

WORKDIR /app

ENV NODE_ENV=production
ENV BFSIBOARD_PORT=8080
ENV BFSIBOARD_SCAN_PATH=/data
ENV BFSIBOARD_SCAN_INTERVAL=900

COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

COPY . .

EXPOSE 8080
VOLUME /data

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://127.0.0.1:8080/api/health',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"

CMD ["node", "server/index.js"]
