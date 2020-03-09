# NOTE: Only use this when you want to build image locally
#       else use `docker pull bcsecurity/empire:{VERSION}`
#       all image versions can be found at: https://hub.docker.com/r/bcsecurity/empire/

# -----BUILD COMMANDS----
# 1) build command: `docker build -t bcsecurity/empire .`
# 2) create volume storage: `docker create -v /empire --name data bcsecurity/empire`
# 3) run out container: `docker run -ti --volumes-from data bcsecurity/empire /bin/bash`

# -----RELEASE COMMANDS----
# Handled by GitHub Actions

# -----BUILD ENTRY-----
#dotnet core
FROM microsoft/dotnet:3.0-sdk AS build
WORKDIR /app

COPY ./data/dotnet/compiler ./
RUN dotnet publish -c Release -o ./bin/out -r linux-x64

