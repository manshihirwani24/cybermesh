FROM node:22-alpine AS dashboard-build
WORKDIR /dashboard
ENV VITE_SHOW_DEFAULT_CREDENTIALS=false
COPY Cybermesh-Security-Dashboard-Source/package*.json ./
RUN npm ci
COPY Cybermesh-Security-Dashboard-Source/ ./
RUN npm run build

FROM node:22-alpine AS app
ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=3001
ENV DATA_DIR=/data
WORKDIR /app
COPY Blockchain/package*.json ./
RUN npm ci --omit=dev --ignore-scripts
COPY Blockchain/server.js Blockchain/scanner.js Blockchain/blockchain.js ./
COPY --from=dashboard-build /dashboard/dist ./public
VOLUME ["/data"]
EXPOSE 3001
CMD ["node", "server.js"]
