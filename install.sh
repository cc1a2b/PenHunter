#!/bin/bash

# Define colors
RED='\033[0;31m'
GREEN='\033[0;32m'
DARK_GREEN='\033[38;5;22m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
MAGENTA='\033[0;35m'
GRAY='\033[0;37m'
BROWN='\033[0;33m'
NC='\033[0m' # No Color

# Update and install basic dependencies
echo -e "${GREEN}Updating package list and installing basic dependencies...${NC}"
sudo apt-get update
sudo apt-get install -y curl git python3 python3-pip tmux

# Install Go
echo -e "${YELLOW}Installing Go...${NC}"
wget https://golang.org/dl/go1.16.4.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.16.4.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go

# Install subfinder
echo -e "${YELLOW}Installing Subfinder...${NC}"
GO111MODULE=on go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
sudo ln -s ~/go/bin/subfinder /usr/local/bin/subfinder

# Install httpx
echo -e "${YELLOW}Installing httpx...${NC}"
GO111MODULE=on go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
sudo ln -s ~/go/bin/httpx /usr/local/bin/httpx

# Install anew
echo -e "${YELLOW}Installing anew...${NC}"
GO111MODULE=on go install -v github.com/tomnomnom/anew@latest
sudo ln -s ~/go/bin/anew /usr/local/bin/anew

# Install katana
echo -e "${YELLOW}Installing Katana...${NC}"
GO111MODULE=on go install -v github.com/projectdiscovery/katana/cmd/katana@latest
sudo ln -s ~/go/bin/katana /usr/local/bin/katana

# Install gau
echo -e "${YELLOW}Installing gau...${NC}"
GO111MODULE=on go install -v github.com/lc/gau/v2/cmd/gau@latest
sudo ln -s ~/go/bin/gau /usr/local/bin/gau

# Install hakrawler
echo -e "${YELLOW}Installing hakrawler...${NC}"
GO111MODULE=on go install -v github.com/hakluke/hakrawler@latest
sudo ln -s ~/go/bin/hakrawler /usr/local/bin/hakrawler

# Install gauplus
echo -e "${YELLOW}Installing gauplus...${NC}"
GO111MODULE=on go install -v github.com/bp0lr/gauplus@latest
sudo ln -s ~/go/bin/gauplus /usr/local/bin/gauplus

# Install gospider
echo -e "${YELLOW}Installing gospider...${NC}"
GO111MODULE=on go install -v github.com/jaeles-project/gospider@latest
sudo ln -s ~/go/bin/gospider /usr/local/bin/gospider

# Install paramspider
echo -e "${YELLOW}Installing ParamSpider...${NC}"
git clone https://github.com/devanshbatham/ParamSpider
cd ParamSpider
pip3 install -r requirements.txt
sudo ln -s $(pwd)/paramspider.py /usr/local/bin/paramspider
cd ..

# Install cariddi
echo -e "${YELLOW}Installing Cariddi...${NC}"
git clone https://github.com/edoardottt/cariddi
cd cariddi
make install
sudo ln -s $(pwd)/cariddi /usr/local/bin/cariddi
cd ..

# Install getJS
echo -e "${YELLOW}Installing getJS...${NC}"
GO111MODULE=on go install -v github.com/003random/getJS@latest
sudo ln -s ~/go/bin/getJS /usr/local/bin/getJS

echo -e "${GREEN}All tools installed successfully!${NC}"
