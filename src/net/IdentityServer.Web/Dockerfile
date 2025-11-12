# syntax=docker/dockerfile:1
# Build stage
FROM mcr.microsoft.com/dotnet/sdk:9.0-alpine AS build
WORKDIR /src

# Copy csproj files and restore dependencies
COPY ["IdentityServer.Web/IdentityServer.Web.csproj", "IdentityServer.Web/"]
RUN dotnet restore "IdentityServer.Web/IdentityServer.Web.csproj"

# Copy the rest of the source code
COPY ["IdentityServer.Web/", "IdentityServer.Web/"]

# Build and publish the Blazor WebAssembly app
WORKDIR "/src/IdentityServer.Web"
ARG BUILD_ENV=Production
RUN dotnet publish "IdentityServer.Web.csproj" -c Release -o /app/publish /p:UseAppHost=false -p:BlazorEnableCompression=false

# Final runtime stage with Nginx
FROM nginx:alpine AS final
WORKDIR /usr/share/nginx/html

# Remove default nginx website
RUN rm -rf ./*

# Copy published Blazor WASM files
COPY --from=build /app/publish/wwwroot .

# Copy custom nginx configuration
COPY ["IdentityServer.Web/nginx.conf", "/etc/nginx/nginx.conf"]

# Create a non-root user for nginx
RUN addgroup -g 1000 appuser && \
    adduser -u 1000 -G appuser -s /bin/sh -D appuser && \
    chown -R appuser:appuser /usr/share/nginx/html && \
    chown -R appuser:appuser /var/cache/nginx && \
    chown -R appuser:appuser /var/log/nginx && \
    chown -R appuser:appuser /etc/nginx/conf.d && \
    touch /var/run/nginx.pid && \
    chown -R appuser:appuser /var/run/nginx.pid

# Switch to non-root user
USER appuser

# Expose port 8080 (non-privileged port)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Start Nginx
CMD ["nginx", "-g", "daemon off;"]
