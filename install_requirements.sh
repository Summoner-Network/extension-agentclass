#!/usr/bin/env bash
set -euo pipefail

# Colors
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
MAGENTA="\033[0;35m"
CYAN="\033[0;36m"
BOLD="\033[1m"
RESET="\033[0m"

# Pretty header function
print_section() {
  local color="$1"
  local title="$2"
  echo -e "${color}${BOLD}==============${RESET}"
  echo -e "${color}${BOLD}${title}${RESET}"
  echo -e "${color}${BOLD}--------------${RESET}"
}

# Loop through requirements.txt files
for req_file in tests/requirements.txt tests/*/requirements.txt requirements.txt; do
  if [ -f "$req_file" ]; then
    print_section "$CYAN" "📦 Installing from: $req_file"

    print_section "$YELLOW" "📋 REQUIREMENTS"
    cat "$req_file"
    echo ""

    print_section "$GREEN" "⚙️ LOGS"
    if pip install -r "$req_file"; then
      echo -e "${GREEN}${BOLD}✅ Successfully installed from $req_file${RESET}"
    else
      echo -e "${RED}${BOLD}❌ Failed installing from $req_file${RESET}"
      exit 1
    fi

    echo ""
  fi
done
