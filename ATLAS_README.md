## build

docker build -t flaresolverr-fork-base-docker .

## push
1. ensure ECR repo created in account: flaresolverr-fork-base-docker
1. `aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 636578074951.dkr.ecr.us-east-1.amazonaws.com`
1. `docker tag flaresolverr-fork-base-docker:latest 636578074951.dkr.ecr.us-east-1.amazonaws.com/flaresolverr-fork-base-docker:latest`
1. `docker push 636578074951.dkr.ecr.us-east-1.amazonaws.com/flaresolverr-fork-base-docker:latest`