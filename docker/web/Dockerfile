# Build stage
FROM docker.io/node:22-bookworm AS build

WORKDIR /app

COPY web/package.json web/package-lock.json* ./
RUN npm install

COPY web/ .
RUN npx tsc && npx vite build

# Serve stage
FROM docker.io/nginx:bookworm

COPY web/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/ || exit 1
