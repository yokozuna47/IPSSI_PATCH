FROM node:20-alpine AS base
WORKDIR /app
RUN apk add --no-cache curl tzdata

FROM base AS deps
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

FROM node:20-alpine AS production
ENV NODE_ENV=production PORT=8000
RUN addgroup -g 1001 -S nodejs && adduser -S nodejs -u 1001 -G nodejs
WORKDIR /app
RUN mkdir -p /app/logs /app/uploads && chown -R nodejs:nodejs /app
COPY --from=deps --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --chown=nodejs:nodejs ./src ./src
COPY --chown=nodejs:nodejs package*.json ./
USER nodejs
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD node -e "require('http').get('http://localhost:8000/health',(r)=>process.exit(r.statusCode===200?0:1))"
CMD ["node", "src/server.js"]
