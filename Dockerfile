# QualityGuard CLI image for CI pipelines.
#   docker build -t qualityguard .
#   docker run --rm -v "$PWD:/src" qualityguard --path /src --by-folder
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /build
COPY src/ src/
RUN dotnet publish src/QualityGuard.Cli/QualityGuard.Cli.csproj -c Release -o /app --nologo

FROM mcr.microsoft.com/dotnet/runtime:9.0
LABEL org.opencontainers.image.title="QualityGuard" \
      org.opencontainers.image.description="Stateless code quality engine and Quality Gate for CI pipelines" \
      org.opencontainers.image.source="https://github.com/francescopaolopassaro/QualityGuard"
COPY --from=build /app /opt/qualityguard
# The scanned repository is mounted here; reports are written next to it.
WORKDIR /src
ENV DOTNET_NOLOGO=1 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1
ENTRYPOINT ["dotnet", "/opt/qualityguard/QualityGuard.Cli.dll"]
CMD ["--path", "/src"]
