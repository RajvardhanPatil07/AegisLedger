FROM node:24.17.0-alpine3.24@sha256:156b55f92e98ccd5ef49578a8cea0df4679826564bad1c9d4ef04462b9f0ded6 AS build

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
ARG VITE_OIDC_ISSUER=http://localhost:8080/realms/aegisledger
ENV VITE_OIDC_ISSUER=${VITE_OIDC_ISSUER}
RUN npm run build

FROM nginx:1.30.4-alpine3.24-slim@sha256:ddde39c6e51f02fde7410c2e9c234cf2d0a4c7bdbbe176aeb37d8ad7ab4eb58c

COPY nginx.conf /etc/nginx/nginx.conf
COPY --from=build --chown=nginx:nginx /app/dist /usr/share/nginx/html
USER nginx
EXPOSE 8080
