# Bytecode is only valid for the exact Bun version that produced it, so both stages share this tag
ARG BUN_IMAGE=oven/bun:1.4.4-alpine

FROM ${BUN_IMAGE} AS build

WORKDIR /app
COPY package.json ./
COPY src ./src
RUN bun run build

FROM ${BUN_IMAGE}

LABEL org.opencontainers.image.authors="mkuhlmann" \
	org.opencontainers.image.source="https://github.com/mkuhlmann/forward-auth"

ENV NODE_ENV=production

WORKDIR /app
# Owned by root so the runtime user cannot modify the application
COPY --from=build /app/dist ./

# Switch to non-root user
USER bun

EXPOSE 8080
CMD ["bun", "server.js"]
