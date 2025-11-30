# Etapa base (runtime)
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
# Puerto interno de la API
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080

# Etapa de build/publish
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copiamos el csproj y restauramos dependencias
COPY ["6-1.csproj", "."]
RUN dotnet restore "6-1.csproj"

# Copiamos todo el código y compilamos
COPY . .
RUN dotnet publish "6-1.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Etapa final (solo runtime + app publicada)
FROM base AS final
WORKDIR /app
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "6-1.dll"]
