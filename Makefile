CONTAINER_ENGINE := docker
TAG := captive

DJANGO_SECRET := $(shell cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 50 | head -n 1)

SSL_SUBJECT := "/C=DE/ST=SomeState/L=SomeCity/O=PICaptive/OU=reverseproxy/CN=localhost"

.PHONY: cert secrets dev stack stop stop-dev build clean distclean logs logs-dev shell help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

cert: ## Generate self-signed SSL certificates
	@openssl req -x509 -newkey rsa:4096 \
		-keyout templates/pi.key \
		-out templates/pi.pem \
		-sha256 -days 3650 -nodes \
		-subj $(SSL_SUBJECT) 2>/dev/null
	@echo "Certificate generation done: templates/pi.pem, templates/pi.key"

secrets: ## Generate random secret for environment file
	@echo "Generate new secret for environment file"
	@echo "-----------------------------------------"
	@echo "DJANGO_SECRET_KEY=$(DJANGO_SECRET)"
	@echo "-----------------------------------------"
	@echo "Replace this value in environment/application-$(TAG).env"

build: ## Build Docker image
	${CONTAINER_ENGINE} compose build

dev: ## Start development stack (runserver + hot-reload)
	${CONTAINER_ENGINE} compose -f docker-compose.dev.yaml up -d
	@echo
	@echo "PI Captive dev: http://localhost:6000"

stack: cert ## Start production stack (gunicorn + nginx SSL)
	${CONTAINER_ENGINE} compose --env-file=environment/application-${TAG}.env -p ${TAG} up -d
	@echo
	@echo "PI Captive: https://localhost:$$(grep -oP 'PROXY_PORT=\K.*' environment/application-${TAG}.env 2>/dev/null || echo 6443)"

stop: ## Stop production stack
	${CONTAINER_ENGINE} compose -p ${TAG} down

stop-dev: ## Stop development stack
	${CONTAINER_ENGINE} compose -f docker-compose.dev.yaml down

logs: ## Show production app logs
	${CONTAINER_ENGINE} compose -p ${TAG} logs -f app

logs-dev: ## Show development app logs
	${CONTAINER_ENGINE} compose -f docker-compose.dev.yaml logs -f app

shell: ## Open Django shell in dev container
	${CONTAINER_ENGINE} compose -f docker-compose.dev.yaml exec app python manage.py shell

clean: ## Stop and remove containers
	@${CONTAINER_ENGINE} compose -p ${TAG} down 2>/dev/null || true
	@${CONTAINER_ENGINE} compose -f docker-compose.dev.yaml down 2>/dev/null || true

distclean: clean ## Remove containers AND volumes
	@${CONTAINER_ENGINE} compose -p ${TAG} down -v 2>/dev/null || true
	@${CONTAINER_ENGINE} compose -f docker-compose.dev.yaml down -v 2>/dev/null || true
