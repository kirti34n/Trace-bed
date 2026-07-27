# Tracebed dashboard (:8111) — React 18 + Vite + TypeScript + Tailwind.
#
# Stack matches Atom's frontend so these views lift into its Command Center later
# without a rewrite (DECISIONS: dashboard stack).

FROM node:22-alpine AS build

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --no-audit --no-fund

COPY . .
RUN npm run build

FROM nginx:1.27-alpine AS runtime

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 8111
