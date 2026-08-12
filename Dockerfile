FROM node:20-alpine

WORKDIR /app

ENV NODE_ENV=production
ENV BFSIBOARD_PORT=8080
ENV BFSIBOARD_SCAN_PATH=/data
ENV BFSIBOARD_SCAN_INTERVAL=900
ENV BFSIBOARD_FEEDS=https://www.fca.org.uk/news/rss.xml,https://www.sec.gov/news/pressreleases.rss,https://www.federalreserve.gov/feeds/press_all.xml,https://www.finra.org/rss.xml,https://www.bankofengland.co.uk/rss/news,https://blog.pcisecuritystandards.org/blog/rss.xml,https://www.cisa.gov/cybersecurity-advisories/all.xml,https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml
ENV BFSIBOARD_FEED_TTL=1800

COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

COPY . .

EXPOSE 8080
VOLUME /data

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://127.0.0.1:8080/api/health',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"

CMD ["node", "server/index.js"]
