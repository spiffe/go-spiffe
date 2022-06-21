# /bin/sh
docker buildx build --platform linux/amd64 -f server.Dockerfile ./ --tag go-spiffe-server
docker tag go-spiffe-server:latest public.ecr.aws/e3b4k2v5/go-spiffe-server:latest
docker push public.ecr.aws/e3b4k2v5/go-spiffe-server:latest

docker buildx build --platform linux/amd64 -f client.Dockerfile ./ --tag go-spiffe-client
docker tag go-spiffe-client:latest public.ecr.aws/e3b4k2v5/go-spiffe-client:latest
docker push public.ecr.aws/e3b4k2v5/go-spiffe-client:latest