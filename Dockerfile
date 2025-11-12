FROM oven/bun:1.3.1-alpine

LABEL AUTHOR mkuhlmann

# Create a non-root user with UID 1000
RUN adduser -D -u 1000 -h /app appuser

WORKDIR /app
COPY --chown=appuser:appuser . .

# Switch to non-root user
USER appuser

EXPOSE 8080
CMD ["bun", "start"]