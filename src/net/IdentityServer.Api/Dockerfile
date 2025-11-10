# syntax=docker/dockerfile:1
# Build stage
FROM mcr.microsoft.com/dotnet/sdk:9.0-alpine AS build
WORKDIR /src

# Copy csproj files and restore dependencies
COPY ["IdentityServer.Api/IdentityServer.Api.csproj", "IdentityServer.Api/"]
COPY ["IdentityServer.Core/IdentityServer.Core.csproj", "IdentityServer.Core/"]
RUN dotnet restore "IdentityServer.Api/IdentityServer.Api.csproj"

# Copy the rest of the source code
COPY ["IdentityServer.Api/", "IdentityServer.Api/"]
COPY ["IdentityServer.Core/", "IdentityServer.Core/"]

# Build the application
WORKDIR "/src/IdentityServer.Api"
RUN dotnet build "IdentityServer.Api.csproj" -c Release -o /app/build

# Publish stage
FROM build AS publish
RUN dotnet publish "IdentityServer.Api.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Final runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:9.0-alpine AS final
WORKDIR /app

# Create a non-root user
RUN addgroup -g 1000 appuser && \
    adduser -u 1000 -G appuser -s /bin/sh -D appuser && \
    chown -R appuser:appuser /app

# Copy published files
COPY --from=publish --chown=appuser:appuser /app/publish .

# Switch to non-root user
USER appuser

# Expose ports
EXPOSE 8080
EXPOSE 8081

# Set environment variables
ENV ASPNETCORE_URLS=http://+:8080 \
    ASPNETCORE_ENVIRONMENT=Production \
    DOTNET_RUNNING_IN_CONTAINER=true \
    DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=false

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Set entrypoint
ENTRYPOINT ["dotnet", "IdentityServer.Api.dll"]
