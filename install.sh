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
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if ! command -v "$PYTHON" &>/dev/null; then
    echo -e "${RED}[!] python3 not found. Install Python 3.10+${NC}"
    exit 1
fi

if ! "$PYTHON" -c 'import sys; sys.exit(sys.version_info < (3, 10))'; then
    echo -e "${RED}[!] Serket requires Python 3.10 or later.${NC}"
    exit 1
fi

PY_VER=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo -e "${GREEN}[+] Python ${PY_VER} detected${NC}"

# Create virtualenv if requested
if [ "${1:-}" = "--venv" ]; then
    echo -e "${YELLOW}[*] Creating virtual environment...${NC}"
    "$PYTHON" -m venv "$SCRIPT_DIR/.venv"
    PYTHON="$SCRIPT_DIR/.venv/bin/python"
    echo -e "${GREEN}[+] venv created at $SCRIPT_DIR/.venv${NC}"
fi

echo -e "${YELLOW}[*] Installing Serket and its dependencies...${NC}"
"$PYTHON" -m pip install --upgrade pip -q
"$PYTHON" -m pip install "$SCRIPT_DIR" -q

echo -e "${GREEN}[+] Done.${NC}"
echo ""
echo -e "  Usage:"
if [ "${1:-}" = "--venv" ]; then
    echo -e "    ${YELLOW}source \"$SCRIPT_DIR/.venv/bin/activate\"${NC}"
fi
echo -e "    ${YELLOW}serket -d <domain> -u <user> --ldaps${NC}"
echo -e "    ${YELLOW}serket -d <domain> -u <user> --hashes :<NT>${NC}"
echo -e "    ${YELLOW}serket -d <domain> -u <user> -k${NC}"
echo -e "    ${YELLOW}serket --load results/serket_corp_*.json${NC}"
echo ""
echo -e "  ${RED}Authorized security testing environments only.${NC}"
