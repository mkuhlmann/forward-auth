FROM oven/bun:1.4.4-alpine

LABEL org.opencontainers.image.authors="mkuhlmann" \
	org.opencontainers.image.source="https://github.com/mkuhlmann/forward-auth"

ENV NODE_ENV=production

WORKDIR /app
# Owned by root so the runtime user cannot modify the application
COPY package.json ./
COPY src ./src

# Switch to non-root user
USER bun

EXPOSE 8080
CMD ["bun", "src/index.ts"]
