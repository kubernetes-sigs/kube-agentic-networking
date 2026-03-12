# Simple Dockerfile that runs the published mcp-everything server package via npx.
# Quick & minimal — no build step, downloads package at container start.
FROM node:20-slim

WORKDIR /app

ENV PORT=3001
EXPOSE 3001

# Use npx to run the streamableHttp server entrypoint.
CMD ["npx", "-y", "@modelcontextprotocol/server-everything@2026.1.14", "streamableHttp"]
