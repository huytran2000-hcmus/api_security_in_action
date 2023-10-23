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

## run: run natter's services
.PHONY: run
run:
	kubectl apply -f kubernetes/natter-namespace.yaml
	kubectl apply -f kubernetes/natter-service-accounts.yaml
	kubectl apply -f kubernetes/natter-database-service.yaml
	kubectl apply -f kubernetes/natter-link-preview-service.yaml
	kubectl apply -f kubernetes/natter-api-service.yaml
	kubectl apply -f kubernetes/natter-database-deployment.yaml
	kubectl apply -f kubernetes/natter-link-preview-deployment.yaml
	kubectl apply -f kubernetes/natter-api-deployment.yaml

## start: build and run natter's services 
.PHONY: start
start: build run
## context: set kubernetes context
context:
	kubectl config set-context --current --namespace natter-api
## restart: restart all natter's deployments
.PHONY: 
restart: context
	kubectl rollout restart deployment natter-api-deployment
	kubectl rollout restart deployment natter-link-preview-deployment
	kubectl rollout restart deployment natter-database-deployment

## shutdown: shut down natter
shutdown: context
	kubectl delete --all service
	kubectl delete --all deployment
	kubectl delete --all serviceaccounts
	kubectl config set-context --current --namespace default
	kubectl delete namespace natter-api

## mesh: service mesh natter
mesh: context
	kubectl get -n natter-api deploy -o yaml | linkerd inject - | kubectl apply -f -