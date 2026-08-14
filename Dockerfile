FROM node:20-alpine

WORKDIR /app

# Install ClamAV (optional, for real malware scanning)
RUN apk add --no-cache clamav clamav-daemon freshclam || true
RUN freshclam || true

# Install dependencies
COPY package*.json ./
RUN npm ci --only=production --legacy-peer-deps

# Copy application
COPY . .

# Create required directories
RUN mkdir -p data/demo-logs data/vault docs

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s \
  CMD wget -qO- http://localhost:3000/api/status || exit 1

CMD ["node", "server.js"]
