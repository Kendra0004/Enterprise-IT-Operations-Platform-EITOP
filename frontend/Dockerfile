# Multi-stage build: compile SPA, serve with nginx.
# Debian-based (not alpine): rollup's musl native binary fails to parse
# @tanstack/react-query on alpine ("Code is nested too deeply").
FROM node:22-bookworm-slim AS build
WORKDIR /src
COPY package.json package-lock.json* ./
RUN npm ci || npm install
COPY . .
RUN npm run build

# Unprivileged nginx: runs as uid 101, listens on 8080, temp dirs in /tmp.
# 1.27-alpine shipped alpine 3.21 (EOL) with 68 fixable HIGH/CRITICAL CVEs
# (brotli OOB write, openssl heap overflow) — see Phase 6 audit F-002.
# Pin the supported stable branch + explicit alpine release.
FROM nginxinc/nginx-unprivileged:1.30-alpine3.23
# Security updates published since the base tag was cut; same intent as the
# backend's apt --only-upgrade layer. apk upgrade needs root briefly.
USER root
RUN apk upgrade --no-cache
USER 101
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/dist /usr/share/nginx/html
EXPOSE 8080
