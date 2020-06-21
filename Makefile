#####################################
## PROJECT SETTINGS #################

PACKAGE = moproxy

MAIN_FILE_IN = bin/moproxy.go
MAIN_FILE_OUT = bin/moproxy
VALID_COMMIT = 22324cad737cdeff930b8f6793c8182ba278a84e

INSTALL_BASE = /opt

######################################
## CONFIGURATION #####################

GO = go

######################################
## MAKEFILE LOGIC ####################

### Executables check
ifeq (, $(shell which $(GO)))
$(error go compiler not found, get the latest version from https://golang.org/dl/)
endif

### Path configuration
BASE = $(CURDIR)
INSTALL_PATH = $(INSTALL_BASE)/$(PACKAGE)

### Verbosity variables
Q=$(if $V,,@)
QV=$(if $V,-v,)

### Setup version variable
COMMIT = $(shell git rev-parse --short HEAD 2>/dev/null)
TAG_NAME = $(shell git describe --tags HEAD 2>/dev/null)
BRANCH = $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null)
VERSION = $(BRANCH)-$(COMMIT)

CLEAN_TREE = $(shell git status --untracked-files=no --porcelain 2>/dev/null)
ifneq ($(CLEAN_TREE),)
    VERSION := $(VERSION)-dirty
endif

VALID_REPO = $(shell git merge-base --is-ancestor $(COMMIT) $(VALID_COMMIT) 2>/dev/null ; echo $$?)
ifneq ($(VALID_REPO),1)
    VERSION = dev
endif

ifneq ($(TAG_NAME),)
	VERSION := $(TAG_NAME) ($(VERSION))
endif

### Compiler flags
LDFLAGS = -ldflags '-X "main.VERSION=$(VERSION)" -s -w'

### Targets
.DEFAULT_GOAL := build

.PHONY: build
build:
	$(info = Building $(PACKAGE) (version $(VERSION)))
	$Q cd $(BASE) && $(GO) build -v $(QV) $(LDFLAGS) -o $(MAIN_FILE_OUT) $(MAIN_FILE_IN)


INSTALL_COPY_FILES = configs/moproxy.conf.dist configs/moproxy.service.dist bin/moproxy
INSTALL_CREATE_EMPTY_FOLDERS = logs

.PHONY: install
install:
	$(info = Installing $(PACKAGE) to $(INSTALL_PATH))
	$Q mkdir -p $(INSTALL_PATH)
	$Q mkdir -p $(addprefix $(INSTALL_PATH)/, $(INSTALL_CREATE_EMPTY_FOLDERS))
	$Q cp -ar --parents  $(INSTALL_COPY_FILES) $(INSTALL_PATH)/

.PHONY: install-systemd
install-systemd:
	$(info = Installing systemd service)

	$Q cp -ar $(INSTALL_PATH)/configs/moproxy.service.dist $(INSTALL_PATH)/configs/moproxy.service
	$Q ln -s $(INSTALL_PATH)/configs/moproxy.service /etc/systemd/system/moproxy.service
	$Q systemctl enable moproxy.service

