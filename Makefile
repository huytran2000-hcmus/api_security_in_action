# ==================================================================================== #
# HELPERS
# ==================================================================================== #

## help: print this help message
.PHONY: help
help:
	@echo 'Usage:'
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | sed -e 's/^/ /'

# ==================================================================================== #
# DEVELOPMENT
# ==================================================================================== #

## build: build natter's images
.PHONY: build 
build:
	eval $(minikube docker-env);
	docker build -t apisecurityinaction/h2database ./docker/h2/;
	mvn clean compile jib:dockerBuild;
	mvn clean compile jib:dockerBuild -Djib.to.image=apisecurityinaction/link-preview -Djib.container.mainClass=com.manning.apisecurityinaction.LinkPreviewer;

## run: build and run natter's services
.PHONY: run
run: build
	kubectl apply -f kubernetes/natter-namespace.yaml
	kubectl apply -f kubernetes/natter-database-deployment.yaml
	kubectl apply -f kubernetes/natter-database-service.yaml
	kubectl apply -f kubernetes/natter-link-preview-deployment.yaml
	kubectl apply -f kubernetes/natter-link-preview-service.yaml
	kubectl apply -f kubernetes/natter-api-deployment.yaml
	kubectl apply -f kubernetes/natter-api-service.yaml

## context: set kubernetes context
context:
	kubectl config set-context --current --namespace natter-api
## restart: restart all natter's deployments
.PHONY: 
restart: context
	kubectl rollout restart deployment natter-api-deployment
	kubectl rollout restart deployment link-preview-deployment
	kubectl rollout restart deployment natter-database-deployment
