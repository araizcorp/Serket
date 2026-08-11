#!/usr/bin/env bash
# Serket — Install script
# AraizCorp LLC | Authorized Security Testing Only

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo -e "${RED}"
echo "   ██████████████████████████████████████"
echo "   █                                    █"
echo "   █   SERKET — AD Attack Path Mapper   █"
echo "   █         AraizCorp LLC              █"
echo "   ██████████████████████████████████████"
echo -e "${NC}"

PYTHON=${PYTHON:-python3}

if ! command -v "$PYTHON" &>/dev/null; then
    echo -e "${RED}[!] python3 not found. Install Python 3.9+${NC}"
    exit 1
fi

PY_VER=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo -e "${GREEN}[+] Python ${PY_VER} detected${NC}"

# Create virtualenv if requested
if [ "${1}" == "--venv" ]; then
    echo -e "${YELLOW}[*] Creating virtual environment...${NC}"
    "$PYTHON" -m venv .venv
    source .venv/bin/activate
    echo -e "${GREEN}[+] venv activated${NC}"
fi

echo -e "${YELLOW}[*] Installing dependencies...${NC}"
"$PYTHON" -m pip install --upgrade pip -q
"$PYTHON" -m pip install -r requirements.txt -q

echo -e "${GREEN}[+] Done.${NC}"
echo ""
echo -e "  Usage:"
echo -e "    ${YELLOW}python serket.py -dc <DC_IP> -d <domain> -u <user> -p <pass>${NC}"
echo -e "    ${YELLOW}python serket.py -dc <DC_IP> -d <domain> -u <user> --hashes :<NT>${NC}"
echo -e "    ${YELLOW}python serket.py -dc <DC_IP> -d <domain> -u <user> -k${NC}"
echo -e "    ${YELLOW}python serket.py --load results/serket_corp_*.json${NC}"
echo ""
echo -e "  ${RED}Authorized security testing environments only.${NC}"
