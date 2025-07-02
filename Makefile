# Makefile for dep-hallucinator development and production

.PHONY: help install install-dev install-prod install-full test coverage lint format type-check security-scan clean build publish validate-release health-check
.PHONY: docker-build docker-run docker-prod docker-dev docker-hpc compose-up deploy performance-check

# Variables
VERSION ?= 1.0.0
DOCKER_REGISTRY ?= dep-hallucinator
DOCKER_TAG ?= latest

# Default target
help:
	@echo "🔍 Dep-Hallucinator Makefile Help"
	@echo "=================================="
	@echo ""
	@echo "📦 Installation:"
	@echo "  install          Install minimal dependencies"
	@echo "  install-dev      Install development dependencies"
	@echo "  install-prod     Install production dependencies"
	@echo "  install-full     Install all features"
	@echo ""
	@echo "🧪 Testing:"
	@echo "  test             Run all tests"
	@echo "  coverage         Generate coverage report"
	@echo ""
	@echo "🛠️  Code Quality:"
	@echo "  lint             Run linting checks"
	@echo "  format           Format code with black and ruff"
	@echo "  type-check       Run type checking with mypy"
	@echo "  security-scan    Run security scanning"
	@echo ""
	@echo "📦 Building:"
	@echo "  build            Build the package for distribution"
	@echo "  publish          Publish to PyPI (requires credentials)"
	@echo "  validate-release Validate package before release"
	@echo ""
	@echo "🐳 Docker:"
	@echo "  docker-build     Build production Docker image"
	@echo "  docker-run       Run Docker container"
	@echo "  docker-prod      Run production container"
	@echo "  docker-dev       Run development container"
	@echo "  docker-hpc       Run high-performance container"
	@echo ""
	@echo "📊 Deployment:"
	@echo "  compose-up       Start with docker-compose"
	@echo "  deploy           Deploy to production"
	@echo "  health-check     Run production health checks"
	@echo "  performance-check  Check performance stats"
	@echo ""
	@echo "🧹 Cleanup:"
	@echo "  clean            Clean up temporary files and build artifacts"

# Installation targets
install:
	pip install -e .

install-prod:
	pip install -e ".[production,rich]"

install-full:
	pip install -e ".[all]"

# Docker targets
docker-build:
	docker build --target production --build-arg BUILD_ENV=production \
		-t $(DOCKER_REGISTRY):$(DOCKER_TAG) \
		-t $(DOCKER_REGISTRY):production .

docker-run:
	docker run -it --rm $(DOCKER_REGISTRY):$(DOCKER_TAG) --help

docker-prod:
	docker run -it --rm \
		--memory=512m --cpus=0.5 \
		-v $(PWD)/data:/app/data:rw \
		-v $(PWD)/logs:/app/logs:rw \
		-e DEP_HALLUCINATOR_PRODUCTION=true \
		$(DOCKER_REGISTRY):production

docker-dev:
	docker build --target development --build-arg BUILD_ENV=development \
		-t $(DOCKER_REGISTRY):dev .
	docker run -it --rm \
		-v $(PWD):/app:rw \
		-e DEP_HALLUCINATOR_ENV=development \
		$(DOCKER_REGISTRY):dev bash

docker-hpc:
	docker build --target production --build-arg BUILD_ENV=full \
		-t $(DOCKER_REGISTRY):hpc .
	docker run -it --rm \
		--memory=1g --cpus=1.0 \
		-v $(PWD)/data:/app/data:rw \
		-e DEP_HALLUCINATOR_ENV=high-performance \
		$(DOCKER_REGISTRY):hpc

# Docker Compose
compose-up:
	docker compose up dep-hallucinator

compose-down:
	docker compose down

# Deployment
deploy: docker-build
	@echo "🚀 Deploying to production..."
	docker tag $(DOCKER_REGISTRY):$(DOCKER_TAG) $(DOCKER_REGISTRY):$(VERSION)
	docker compose up -d dep-hallucinator

performance-check:
	@echo "📊 Checking performance..."
	DEP_HALLUCINATOR_PRODUCTION=true \
	DEP_HALLUCINATOR_ENABLE_METRICS=true \
	dep-hallucinator --performance-stats

# Production targets
build:
	python -m build
	@echo "✅ Package built successfully"
	@echo "📦 Files created in dist/"
	ls -la dist/

publish: validate-release
	@echo "🚀 Publishing to PyPI..."
	python -m twine upload dist/*
	@echo "✅ Package published successfully"

validate-release: build
	@echo "🔍 Validating package..."
	python -m twine check dist/*
	python -c "import tarfile; import zipfile; print('📦 Checking package contents...'); [print(f'  {f}') for f in tarfile.open('dist/dep-hallucinator-1.0.0.tar.gz').getnames()[:10]]"
	@echo "✅ Package validation complete"

health-check:
	@echo "🏥 Running production health checks..."
	python -c "import dep_hallucinator; print('✅ Package imports successfully')"
	dep-hallucinator --version
	@echo "🔍 Testing sample scan..."
	echo "requests==2.28.1" > /tmp/health_check_deps.txt
	dep-hallucinator scan /tmp/health_check_deps.txt --quiet
	rm -f /tmp/health_check_deps.txt
	@echo "✅ Health check passed"

# Development targets
install-dev:
	pip install -e ".[dev,test]"

test:
	pytest tests/ -v

coverage:
	pytest tests/ --cov=src/dep_hallucinator --cov-report=html --cov-report=term --cov-fail-under=85

lint:
	ruff check src/ tests/
	mypy src/

format:
	black src/ tests/
	ruff format src/ tests/

type-check:
	mypy src/ --strict

security-scan:
	bandit -r src/ -f json -o security-report.json || true
	safety check --json --output safety-report.json || true
	@echo "🔒 Security scan complete. Check security-report.json and safety-report.json"

# CI/CD targets
ci-test:
	pytest tests/ -v --cov=src/dep_hallucinator --cov-report=xml --cov-fail-under=85 --junit-xml=test-results.xml

ci-security:
	bandit -r src/ -f json -o bandit-report.json || true
	safety check --json --output safety-report.json || true

ci-quality:
	ruff check src/ tests/ --output-format=json --output-file=ruff-report.json || true
	mypy src/ --junit-xml mypy-report.xml || true

# Clean up
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf coverage.xml
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	rm -rf security-report.json
	rm -rf safety-report.json
	rm -rf test-results.xml
	rm -rf ruff-report.json
	rm -rf mypy-report.xml
	@echo "🧹 Cleanup complete" 