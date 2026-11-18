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
FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/dist /usr/share/nginx/html
EXPOSE 8080
