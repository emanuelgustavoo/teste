#!/bin/bash
#
# FFUF MASTER SCRIPT - Bug Bounty Edition v5.1
# Author: @ofjaaah
# Fluxo: subfinder → permutação → puredns → httpx → cdncheck → ffuf (smart wordlist)
# Baseado nas melhores práticas de: jhaddix, tomnomnom, nahamsec, assetnote
#

# Auto-path: Go tools, Cargo, PDtools
export PATH="$HOME/go/bin:$HOME/.cargo/bin:$HOME/.local/bin:$HOME/.pdtm/go/bin:/usr/local/go/bin:/usr/local/bin:$PATH"

# Não parar em erros (para continuar mesmo se um subdomínio falhar)
set +e

# ============================================================================
# CONFIGURAÇÕES GLOBAIS - BUG BOUNTY OPTIMIZED
# ============================================================================

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
ORANGE='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m'

# Versão e tempo de início
SCRIPT_VERSION="5.1"
SCRIPT_START_TIME=$(date +%s)

# Detecção de largura do terminal
get_term_width() {
    local w
    w=$(tput cols 2>/dev/null) || w=${COLUMNS:-80}
    [[ $w -lt 40 ]] && w=80
    echo "$w"
}
TERM_WIDTH=$(get_term_width)
BOX_WIDTH=$((TERM_WIDTH > 80 ? 80 : TERM_WIDTH))
BOX_INNER=$((BOX_WIDTH - 2))

# Diretórios padrão
BASE_DIR="${HOME}/ffuf_scans"
WORDLISTS_DIR="${BASE_DIR}/wordlists"
RESULTS_DIR="${BASE_DIR}/results"
LOGS_DIR="${BASE_DIR}/logs"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Criar estrutura de diretórios
mkdir -p "$WORDLISTS_DIR" "$RESULTS_DIR" "$LOGS_DIR"

# ============================================================================
# CONFIGURAÇÕES FFUF - BUG BOUNTY BEST PRACTICES
# ============================================================================

# Headers realistas (evitar detecção de scanner)
FFUF_HEADERS=(
    -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
    -H "Accept-Language: en-US,en;q=0.9"
    -H "Accept-Encoding: gzip, deflate, br"
    -H "Connection: keep-alive"
    -H "Upgrade-Insecure-Requests: 1"
    -H "Sec-Fetch-Dest: document"
    -H "Sec-Fetch-Mode: navigate"
    -H "Sec-Fetch-Site: none"
    -H "Sec-Fetch-User: ?1"
    -H "Cache-Control: max-age=0"
    -H "DNT: 1"
)

# Configurações padrão otimizadas
DEFAULT_THREADS=30
DEFAULT_RATE=50
DEFAULT_TIMEOUT=10
DEFAULT_RECURSION_DEPTH=3
DEFAULT_MAXTIME=300

# Wordlists preferidas - DIRETÓRIOS (em ordem de prioridade)
WORDLIST_PATHS=(
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt"
    "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt"
    "${WORDLISTS_DIR}/raft-medium.txt"
    "/usr/share/seclists/Discovery/Web-Content/common.txt"
    "/usr/share/wordlists/dirb/common.txt"
)

# Wordlists preferidas - APIs
API_WORDLIST_PATHS=(
    "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt"
    "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt"
    "${WORDLISTS_DIR}/api-master.txt"
    "${WORDLISTS_DIR}/api-endpoints.txt"
)

# Wordlists para bruteforce DNS
DNS_WORDLIST_PATHS=(
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
    "/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt"
    "${WORDLISTS_DIR}/dns-wordlist.txt"
)

# Palavras para permutação de subdomínios
PERMUTATION_WORDS=(
    "api" "dev" "stg" "staging" "prod" "production" "test" "testing"
    "uat" "qa" "beta" "alpha" "demo" "sandbox" "internal" "external"
    "admin" "portal" "app" "mobile" "web" "www" "cdn" "static"
    "assets" "media" "img" "images" "files" "upload" "download"
    "backup" "bak" "old" "new" "v1" "v2" "v3" "api-v1" "api-v2"
    "gateway" "gw" "proxy" "lb" "loadbalancer" "edge" "origin"
    "db" "database" "mysql" "postgres" "redis" "mongo" "elastic"
    "mail" "smtp" "pop" "imap" "mx" "email" "newsletter"
    "vpn" "remote" "ssh" "ftp" "sftp" "git" "gitlab" "github"
    "jenkins" "ci" "cd" "deploy" "release" "build" "artifactory"
    "grafana" "prometheus" "kibana" "logs" "monitoring" "metrics"
    "auth" "sso" "login" "oauth" "identity" "idp" "saml"
    "docs" "documentation" "wiki" "confluence" "jira" "support"
    "shop" "store" "checkout" "payment" "billing" "invoice"
    "crm" "erp" "hr" "finance" "sales" "marketing"
)

# ============================================================================
# UTILIDADES VISUAIS
# ============================================================================

# Strip ANSI escape sequences para calcular comprimento real
strip_ansi() { sed 's/\x1b\[[0-9;]*m//g' <<< "$1"; }

# Desenhar linhas de caixa Unicode
# Uso: draw_line top|mid|bot|sep
draw_line() {
    local kind="${1:-mid}"
    local fill
    fill=$(printf '═%.0s' $(seq 1 "$BOX_INNER"))
    case "$kind" in
        top) echo -e "${CYAN}${BOLD}╔${fill}╗${NC}" ;;
        mid) echo -e "${CYAN}${BOLD}╠${fill}╣${NC}" ;;
        bot) echo -e "${CYAN}${BOLD}╚${fill}╝${NC}" ;;
        sep) echo -e "${CYAN}${BOLD}║${NC}$(printf '─%.0s' $(seq 1 "$BOX_INNER"))${CYAN}${BOLD}║${NC}" ;;
    esac
}

# Texto centralizado dentro da caixa
box_center() {
    local text="$1"
    local color="${2:-$CYAN$BOLD}"
    local plain
    plain=$(strip_ansi "$text")
    local len=${#plain}
    local pad=$(( (BOX_INNER - len) / 2 ))
    [[ $pad -lt 0 ]] && pad=0
    local rpad=$(( BOX_INNER - len - pad ))
    [[ $rpad -lt 0 ]] && rpad=0
    printf "%b║%b%*s%b%*s%b║%b\n" "${CYAN}${BOLD}" "${NC}${color}" "$pad" "" "$text" "$rpad" "" "${NC}${CYAN}${BOLD}" "${NC}"
}

# Texto alinhado à esquerda dentro da caixa (2 espaços de padding)
box_left() {
    local text="$1"
    local plain
    plain=$(strip_ansi "$text")
    local len=${#plain}
    local rpad=$((BOX_INNER - 2 - len))
    [[ $rpad -lt 0 ]] && rpad=0
    printf "%b║%b  %b%*s%b║%b\n" "${CYAN}${BOLD}" "${NC}" "$text" "$rpad" "" "${CYAN}${BOLD}" "${NC}"
}

# Linha vazia dentro da caixa
box_empty() {
    printf "%b║%b%*s%b║%b\n" "${CYAN}${BOLD}" "${NC}" "$BOX_INNER" "" "${CYAN}${BOLD}" "${NC}"
}

# Barra de progresso: show_progress current total label [start_time]
show_progress() {
    local current=$1 total=$2 label="$3" start=${4:-}
    [[ $total -eq 0 ]] && return
    local pct=$((current * 100 / total))
    local bar_len=30
    local filled=$((pct * bar_len / 100))
    local empty=$((bar_len - filled))
    local bar
    bar=$(printf '█%.0s' $(seq 1 "$filled") 2>/dev/null)
    bar+=$(printf '░%.0s' $(seq 1 "$empty") 2>/dev/null)
    local time_str=""
    if [[ -n "$start" ]]; then
        local elapsed=$(( $(date +%s) - start ))
        time_str=" $(format_elapsed $elapsed)"
    fi
    printf "\r  ${CYAN}%s${NC} [${GREEN}%s${NC}] %3d%% (%d/%d)%s" "$label" "$bar" "$pct" "$current" "$total" "$time_str"
}

# Spinner Braille animado
start_spinner() {
    local msg="${1:-Processando...}"
    local spin_chars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    (
        local i=0
        while true; do
            printf "\r  ${CYAN}%s${NC} %s" "${spin_chars:$((i % ${#spin_chars})):1}" "$msg"
            i=$((i + 1))
            sleep 0.1
        done
    ) &
    SPINNER_PID=$!
    disown $SPINNER_PID 2>/dev/null
}

stop_spinner() {
    local pid="${1:-$SPINNER_PID}"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null
    fi
    printf "\r\033[K"
    SPINNER_PID=""
}

# Formatar segundos em tempo legível
format_elapsed() {
    local secs=$1
    if [[ $secs -ge 3600 ]]; then
        printf "%dh%02dm%02ds" $((secs/3600)) $(( (secs%3600)/60 )) $((secs%60))
    elif [[ $secs -ge 60 ]]; then
        printf "%dm%02ds" $((secs/60)) $((secs%60))
    else
        printf "%ds" "$secs"
    fi
}

# Rastrear tempo por fase
PHASE_START_TIME=0
start_phase_timer() { PHASE_START_TIME=$(date +%s); }
end_phase_timer() {
    local elapsed=$(( $(date +%s) - PHASE_START_TIME ))
    if [[ $elapsed -gt 0 ]]; then
        echo -e "  ${CYAN}⏱  Fase concluída em${NC} ${BOLD}$(format_elapsed $elapsed)${NC}"
    fi
}

# Formatar resultado com cores por status HTTP
format_result() {
    local status="$1" url="$2" bytes="$3"
    local color="$NC"
    case "$status" in
        200|201|204) color="$GREEN" ;;
        301|302|307|308) color="$BLUE" ;;
        401|403|405) color="$YELLOW" ;;
        500|502|503) color="$RED" ;;
    esac
    printf "  ${color}%-6s${NC} %-60s %s\n" "[$status]" "$url" "$bytes"
}

# Trap para limpar spinner em caso de Ctrl+C
cleanup_spinner() {
    [[ -n "${SPINNER_PID:-}" ]] && stop_spinner "$SPINNER_PID"
}
trap 'cleanup_spinner' EXIT INT TERM

# ============================================================================
# VERIFICAÇÃO DE DEPENDÊNCIAS
# ============================================================================

check_dependencies() {
    local missing=()
    local optional_missing=()

    # Dependências obrigatórias
    local required_tools=("ffuf" "curl" "dig")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing+=("$tool")
        fi
    done

    # Dependências opcionais mas recomendadas
    local optional_tools=("python3" "timeout" "openssl" "subfinder" "httpx" "puredns" "katana" "gospider" "gau" "cdncheck")
    for tool in "${optional_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            optional_missing+=("$tool")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}[✗] Dependências obrigatórias não encontradas:${NC}"
        for tool in "${missing[@]}"; do
            echo -e "    - $tool"
        done
        echo ""
        echo "Instale com:"
        echo "  ffuf: go install github.com/ffuf/ffuf/v2@latest"
        echo "  curl: apt install curl"
        echo "  dig:  apt install dnsutils"
        return 1
    fi

    if [[ ${#optional_missing[@]} -gt 0 ]]; then
        echo -e "${YELLOW}[!] Dependências opcionais não encontradas:${NC}"
        for tool in "${optional_missing[@]}"; do
            echo -e "    - $tool"
        done
        echo ""
    fi

    return 0
}

# ============================================================================
# SETUP AUTOMÁTICO - INSTALA FERRAMENTAS + WORDLISTS
# ============================================================================

setup_all() {
    draw_line "top"
    box_center "${BOLD}FFUF MASTER - SETUP AUTOMÁTICO v${SCRIPT_VERSION}${NC}"
    draw_line "mid"
    box_empty
    box_left "Instalação completa: ferramentas + wordlists"
    box_empty
    draw_line "bot"
    echo ""

    local failed=()
    local installed=()
    local skipped=()

    # ── FASE 1: Dependências do sistema ──────────────────────────────────
    log_phase "DEPENDÊNCIAS DO SISTEMA" "1" "5"

    log_info "Atualizando repositórios apt..."
    apt-get update -qq 2>/dev/null

    local apt_packages=("curl" "dnsutils" "python3" "coreutils" "openssl" "whois" "flock" "parallel" "jq" "unzip" "git")
    for pkg in "${apt_packages[@]}"; do
        # Map package name to binary name for checking
        local bin="$pkg"
        case "$pkg" in
            dnsutils) bin="dig" ;;
            coreutils) bin="timeout" ;;
        esac

        if command -v "$bin" &>/dev/null; then
            skipped+=("$pkg")
            log_success "$pkg já instalado"
        else
            log_info "Instalando $pkg..."
            if apt-get install -y -qq "$pkg" 2>/dev/null; then
                installed+=("$pkg")
                log_success "$pkg instalado"
            else
                failed+=("$pkg (apt)")
                log_error "Falha ao instalar $pkg"
            fi
        fi
    done

    # ── FASE 2: Go (necessário para ferramentas ProjectDiscovery) ────────
    log_phase "GOLANG" "2" "5"

    if command -v go &>/dev/null; then
        local go_ver
        go_ver=$(go version 2>/dev/null | grep -oP 'go\d+\.\d+')
        skipped+=("go")
        log_success "Go já instalado ($go_ver)"
    else
        log_info "Instalando Go (última versão estável)..."
        local go_latest
        go_latest=$(curl -sL 'https://go.dev/VERSION?m=text' | head -1)
        if [[ -n "$go_latest" ]]; then
            local go_tar="${go_latest}.linux-amd64.tar.gz"
            log_info "Baixando ${go_tar}..."
            if curl -sL "https://go.dev/dl/${go_tar}" -o "/tmp/${go_tar}"; then
                rm -rf /usr/local/go
                tar -C /usr/local -xzf "/tmp/${go_tar}"
                rm -f "/tmp/${go_tar}"
                export PATH="/usr/local/go/bin:${HOME}/go/bin:${PATH}"
                # Persistir no profile
                if ! grep -q '/usr/local/go/bin' "${HOME}/.bashrc" 2>/dev/null; then
                    echo 'export PATH="/usr/local/go/bin:${HOME}/go/bin:${PATH}"' >> "${HOME}/.bashrc"
                fi
                installed+=("go")
                log_success "Go instalado ($(go version 2>/dev/null | grep -oP 'go\d+\.\d+'))"
            else
                failed+=("go")
                log_error "Falha ao baixar Go"
            fi
        else
            failed+=("go")
            log_error "Não conseguiu detectar versão do Go"
        fi
    fi

    # Garantir GOPATH no PATH
    export PATH="/usr/local/go/bin:${HOME}/go/bin:${PATH}"

    # ── FASE 3: Ferramentas Go (ProjectDiscovery + ffuf + gau) ───────────
    log_phase "FERRAMENTAS DE RECON" "3" "5"

    # Mapa: ferramenta → go install path
    declare -A GO_TOOLS=(
        ["ffuf"]="github.com/ffuf/ffuf/v2@latest"
        ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
        ["puredns"]="github.com/d3mondev/puredns/v2@latest"
        ["dnsx"]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        ["katana"]="github.com/projectdiscovery/katana/cmd/katana@latest"
        ["tldfinder"]="github.com/projectdiscovery/tldfinder/cmd/tldfinder@latest"
        ["gau"]="github.com/lc/gau/v2/cmd/gau@latest"
        ["gospider"]="github.com/jaeles-project/gospider@latest"
        ["cdncheck"]="github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"
    )

    # Ordem de instalação (obrigatórias primeiro)
    local tool_order=("ffuf" "subfinder" "httpx" "puredns" "dnsx" "katana" "tldfinder" "gau" "gospider" "cdncheck")

    if ! command -v go &>/dev/null; then
        log_error "Go não disponível — pulando ferramentas Go"
        for t in "${tool_order[@]}"; do
            command -v "$t" &>/dev/null || failed+=("$t (sem Go)")
        done
    else
        local total=${#tool_order[@]}
        local current=0
        for tool in "${tool_order[@]}"; do
            current=$((current + 1))
            if command -v "$tool" &>/dev/null; then
                skipped+=("$tool")
                log_success "[$current/$total] $tool já instalado ($(command -v "$tool"))"
            else
                log_info "[$current/$total] Instalando $tool..."
                if go install -v "${GO_TOOLS[$tool]}" 2>/dev/null; then
                    installed+=("$tool")
                    log_success "[$current/$total] $tool instalado"
                else
                    failed+=("$tool (go install)")
                    log_error "[$current/$total] Falha ao instalar $tool"
                fi
            fi
        done
    fi

    # ── FASE 4: Download de Wordlists ────────────────────────────────────
    log_phase "WORDLISTS" "4" "5"
    download_wordlists

    # ── FASE 5: Verificação Final ────────────────────────────────────────
    log_phase "VERIFICAÇÃO FINAL" "5" "5"

    echo ""
    draw_line "top"
    box_center "${BOLD}RESULTADO DO SETUP${NC}"
    draw_line "mid"
    box_empty

    # Ferramentas instaladas
    if [[ ${#installed[@]} -gt 0 ]]; then
        box_left "${GREEN}✓ INSTALADOS (${#installed[@]}):${NC}"
        local line=""
        for item in "${installed[@]}"; do
            if [[ ${#line} -gt 0 ]]; then
                line="${line}, ${item}"
            else
                line="  ${item}"
            fi
            if [[ ${#line} -gt 60 ]]; then
                box_left "$line"
                line=""
            fi
        done
        [[ -n "$line" ]] && box_left "$line"
        box_empty
    fi

    # Já existentes
    if [[ ${#skipped[@]} -gt 0 ]]; then
        box_left "${CYAN}● JÁ EXISTENTES (${#skipped[@]}):${NC}"
        local line=""
        for item in "${skipped[@]}"; do
            if [[ ${#line} -gt 0 ]]; then
                line="${line}, ${item}"
            else
                line="  ${item}"
            fi
            if [[ ${#line} -gt 60 ]]; then
                box_left "$line"
                line=""
            fi
        done
        [[ -n "$line" ]] && box_left "$line"
        box_empty
    fi

    # Falhas
    if [[ ${#failed[@]} -gt 0 ]]; then
        box_left "${RED}✗ FALHAS (${#failed[@]}):${NC}"
        for item in "${failed[@]}"; do
            box_left "  ${RED}${item}${NC}"
        done
        box_empty
    fi

    draw_line "sep"

    # Status geral das ferramentas
    box_left "${BOLD}${YELLOW}STATUS DAS FERRAMENTAS:${NC}"
    box_empty

    local all_tools=("ffuf" "curl" "dig" "python3" "go" "subfinder" "httpx" "puredns" "dnsx" "katana" "gospider" "gau" "tldfinder" "jq" "parallel" "openssl" "whois")
    for tool in "${all_tools[@]}"; do
        local path
        path=$(command -v "$tool" 2>/dev/null)
        if [[ -n "$path" ]]; then
            box_left "  ${GREEN}✓${NC} ${tool} → ${path}"
        else
            box_left "  ${RED}✗${NC} ${tool} → não encontrado"
        fi
    done

    box_empty
    draw_line "sep"

    # Wordlists
    box_left "${BOLD}${YELLOW}WORDLISTS:${NC}"
    box_empty
    if [[ -d "$WORDLISTS_DIR" ]]; then
        local wl_count
        wl_count=$(find "$WORDLISTS_DIR" -name '*.txt' -type f 2>/dev/null | wc -l)
        local wl_size
        wl_size=$(du -sh "$WORDLISTS_DIR" 2>/dev/null | cut -f1)
        box_left "  Diretório: ${WORDLISTS_DIR}"
        box_left "  Arquivos:  ${wl_count} wordlists"
        box_left "  Tamanho:   ${wl_size}"
        box_empty
        for wl in "$WORDLISTS_DIR"/*.txt; do
            [[ -f "$wl" ]] || continue
            local name lines
            name=$(basename "$wl")
            lines=$(wc -l < "$wl" 2>/dev/null)
            box_left "  ${GREEN}•${NC} ${name} (${lines} linhas)"
        done
    else
        box_left "  ${RED}Nenhuma wordlist encontrada${NC}"
    fi

    box_empty
    draw_line "sep"

    # Como usar
    box_left "${BOLD}${YELLOW}COMO USAR:${NC}"
    box_empty
    box_left "  ${GREEN}Scan rápido:${NC}"
    box_left "    ./ffuf_master.sh https://target.com"
    box_empty
    box_left "  ${GREEN}Hunt mode:${NC}"
    box_left "    ./ffuf_master.sh --hunt target.com"
    box_empty
    box_left "  ${GREEN}Full recon:${NC}"
    box_left "    ./ffuf_master.sh --domains target.com"
    box_empty
    box_left "  ${GREEN}Loot mode:${NC}"
    box_left "    ./ffuf_master.sh --loot <hunt_results_dir>"
    box_empty
    box_left "  ${GREEN}Ajuda completa:${NC}"
    box_left "    ./ffuf_master.sh --help"
    box_empty
    draw_line "bot"

    if [[ ${#failed[@]} -gt 0 ]]; then
        echo ""
        log_warning "Algumas instalações falharam. Verifique acima."
        return 1
    else
        echo ""
        log_success "Setup completo! Todas as ferramentas prontas."
        return 0
    fi
}

# ============================================================================
# FUNÇÕES AUXILIARES
# ============================================================================

log_info() { echo -e "${CYAN}[*]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }
log_phase() {
    local title="$1" step="${2:-}" total="${3:-}"
    # End previous phase timer if active
    [[ $PHASE_START_TIME -gt 0 ]] && end_phase_timer
    echo ""
    local fill
    fill=$(printf '═%.0s' $(seq 1 "$BOX_INNER"))
    echo -e "${MAGENTA}${BOLD}╠${fill}╣${NC}"
    local label="$title"
    [[ -n "$step" && -n "$total" ]] && label="[$step/$total] $title"
    local plain
    plain=$(strip_ansi "$label")
    local len=${#plain}
    local pad=$(( (BOX_INNER - len) / 2 ))
    [[ $pad -lt 0 ]] && pad=0
    local rpad=$(( BOX_INNER - len - pad ))
    [[ $rpad -lt 0 ]] && rpad=0
    printf "${MAGENTA}${BOLD}║${NC}%*s${MAGENTA}${BOLD}%s${NC}%*s${MAGENTA}${BOLD}║${NC}\n" "$pad" "" "$label" "$rpad" ""
    echo -e "${MAGENTA}${BOLD}╠${fill}╣${NC}"
    echo ""
    start_phase_timer
}

# Encontrar wordlist disponível
find_wordlist() {
    local custom_wl="$1"

    # Se especificado, usar esse
    if [[ -n "$custom_wl" && -f "$custom_wl" ]]; then
        echo "$custom_wl"
        return 0
    fi

    # Procurar nas localizações padrão
    for wl in "${WORDLIST_PATHS[@]}"; do
        if [[ -f "$wl" ]]; then
            echo "$wl"
            return 0
        fi
    done

    log_error "Nenhuma wordlist encontrada!"
    log_warning "Execute: ./ffuf_master.sh --download-wordlists"
    return 1
}

# ============================================================================
# SELEÇÃO INTELIGENTE DE WORDLIST
# ============================================================================

# Detectar se URL/host é contexto de API
is_api_context() {
    local url="$1"
    local subdomain=$(echo "$url" | sed -E 's#^https?://##; s#/.*##; s#:[0-9]+##')
    local path=$(echo "$url" | grep -oE '/[^?#]*' | head -1)

    # Verificar subdomínio - API e desenvolvimento
    if echo "$subdomain" | grep -qiE '^(api[0-9]*|api-|apis|gateway|gw|graphql|rest|v[0-9]+|dev[0-9]*|stg|staging|prod|uat|qa|test|sandbox|internal)\.'; then
        return 0
    fi

    # Verificar path
    if echo "$path" | grep -qiE '^/(api|apis|v[0-9]+|graphql|rest|swagger|openapi)/'; then
        return 0
    fi

    # Verificar palavras-chave compostas no subdomínio (dev-api, staging-api, etc)
    if echo "$subdomain" | grep -qiE '(dev|stg|staging|prod|uat|qa|test)[-.]?api'; then
        return 0
    fi

    return 1
}

# Selecionar wordlist baseado no contexto
select_smart_wordlist() {
    local url="$1"
    local force_type="$2"  # "api" ou "dir" para forçar

    # Se forçado, usar o tipo especificado
    if [[ "$force_type" == "api" ]]; then
        find_api_wordlist
        return $?
    elif [[ "$force_type" == "dir" ]]; then
        find_wordlist
        return $?
    fi

    # Detectar automaticamente
    if is_api_context "$url"; then
        find_api_wordlist
    else
        find_wordlist
    fi
}

# Encontrar wordlist de API
find_api_wordlist() {
    # Procurar nas localizações padrão de API
    for wl in "${API_WORDLIST_PATHS[@]}"; do
        if [[ -f "$wl" ]]; then
            echo "$wl"
            return 0
        fi
    done

    # Se não encontrar, criar uma básica
    create_api_wordlist
    echo "${WORDLISTS_DIR}/api-master.txt"
}

# Criar wordlist de API se não existir
create_api_wordlist() {
    local output="${WORDLISTS_DIR}/api-master.txt"
    [[ -f "$output" ]] && return 0

    log_info "Criando wordlist de API..."
    cat > "$output" << 'APIWORDS'
v1
v2
v3
api
users
user
me
profile
account
accounts
auth
login
logout
register
signup
signin
token
refresh
verify
reset
password
forgot
oauth
oauth2
callback
authorize
permissions
roles
admin
admins
administrator
config
configuration
settings
preferences
health
status
ping
info
version
metrics
stats
analytics
dashboard
reports
docs
documentation
swagger
swagger.json
swagger.yaml
swagger-ui
openapi
openapi.json
openapi.yaml
graphql
graphiql
query
mutation
schema
introspection
search
filter
sort
page
limit
offset
list
all
get
create
update
delete
remove
add
edit
patch
put
post
upload
download
export
import
file
files
image
images
media
assets
static
public
private
internal
external
webhook
webhooks
callback
callbacks
event
events
notification
notifications
message
messages
email
emails
sms
push
comment
comments
review
reviews
rating
ratings
like
likes
follow
follows
share
shares
post
posts
article
articles
blog
blogs
news
category
categories
tag
tags
product
products
item
items
order
orders
cart
carts
checkout
payment
payments
transaction
transactions
invoice
invoices
subscription
subscriptions
plan
plans
price
prices
discount
discounts
coupon
coupons
customer
customers
client
clients
vendor
vendors
merchant
merchants
shop
shops
store
stores
inventory
stock
shipping
tracking
address
addresses
location
locations
country
countries
region
regions
city
cities
zip
postal
contact
contacts
lead
leads
ticket
tickets
support
help
faq
feedback
survey
form
forms
template
templates
report
audit
log
logs
activity
history
archive
backup
restore
sync
batch
bulk
async
queue
job
jobs
task
tasks
worker
workers
process
cron
schedule
trigger
hook
hooks
plugin
plugins
extension
extensions
module
modules
service
services
resource
resources
entity
entities
model
models
object
objects
record
records
data
metadata
attribute
attributes
property
properties
field
fields
key
keys
value
values
pair
id
uuid
guid
ref
reference
link
links
url
urls
uri
redirect
debug
test
testing
sandbox
demo
example
sample
mock
fake
dummy
dev
development
stg
staging
prod
production
uat
qa
beta
alpha
preview
release
latest
current
legacy
deprecated
old
new
APIWORDS

    log_success "Wordlist de API criada: $output ($(wc -l < "$output") palavras)"
}

# Encontrar wordlist DNS
find_dns_wordlist() {
    for wl in "${DNS_WORDLIST_PATHS[@]}"; do
        if [[ -f "$wl" ]]; then
            echo "$wl"
            return 0
        fi
    done

    # Criar wordlist básica se não existir
    create_dns_wordlist
    echo "${WORDLISTS_DIR}/dns-wordlist.txt"
}

# Criar wordlist DNS básica
create_dns_wordlist() {
    local output="${WORDLISTS_DIR}/dns-wordlist.txt"
    [[ -f "$output" ]] && return 0

    log_info "Criando wordlist DNS básica..."

    # Combinar palavras comuns
    printf '%s\n' "${PERMUTATION_WORDS[@]}" > "$output"

    # Adicionar números
    for word in api dev test staging prod; do
        for i in {1..5}; do
            echo "${word}${i}"
            echo "${word}-${i}"
        done
    done >> "$output"

    sort -u "$output" -o "$output"
    log_success "Wordlist DNS criada: $output ($(wc -l < "$output") palavras)"
}

# ============================================================================
# PERMUTAÇÃO DE SUBDOMÍNIOS
# ============================================================================

permute_subdomains() {
    local input_file="$1"
    local domain="$2"
    local output_file="$3"

    log_info "Gerando permutações de subdomínios..."

    local temp_permutations=$(mktemp)

    # Extrair prefixos únicos (remover o domínio base e pegar a primeira parte)
    # Escapar metacaracteres regex no domínio
    local escaped_domain=$(printf '%s\n' "$domain" | sed 's/[.[\*^$()+?{}|]/\\&/g')
    local prefixes=$(cat "$input_file" | grep -v "^${escaped_domain}$" | sed "s/\.${escaped_domain}$//" | grep -v '^\.' | sort -u)

    local prefix_count=$(echo "$prefixes" | grep -c . || echo 0)
    log_info "Encontrados $prefix_count prefixos para permutação"

    # Se não encontrou prefixos, usar apenas palavras base
    if [[ $prefix_count -eq 0 ]]; then
        log_warning "Nenhum prefixo encontrado, usando palavras padrão"
        # Gerar apenas com palavras de permutação
        for word in api dev staging test prod uat admin portal; do
            echo "${word}.${domain}"
            echo "${word}1.${domain}"
            echo "${word}2.${domain}"
        done >> "$temp_permutations"
    else
        # Gerar permutações baseadas nos prefixos encontrados
        while IFS= read -r prefix; do
            [[ -z "$prefix" ]] && continue

            # Palavras-chave importantes para permutação
            local key_words=("api" "dev" "stg" "staging" "prod" "test" "uat" "qa" "admin" "portal" "internal" "old" "new" "backup" "v1" "v2")

            for word in "${key_words[@]}"; do
                # Evitar duplicatas
                [[ "$word" == "$prefix" ]] && continue

                # Combinações hífen
                echo "${prefix}-${word}.${domain}"
                echo "${word}-${prefix}.${domain}"

                # Com números
                echo "${prefix}${word}.${domain}"
                echo "${word}${prefix}.${domain}"
            done

            # Variações numéricas do próprio prefixo
            echo "${prefix}1.${domain}"
            echo "${prefix}2.${domain}"
            echo "${prefix}01.${domain}"
            echo "${prefix}-1.${domain}"
            echo "${prefix}-2.${domain}"
            echo "${prefix}-dev.${domain}"
            echo "${prefix}-api.${domain}"
            echo "${prefix}-test.${domain}"
            echo "${prefix}-stg.${domain}"
            echo "${prefix}-prod.${domain}"

        done <<< "$prefixes" >> "$temp_permutations"

        # Combinações entre prefixos existentes
        local prefix_array
        mapfile -t prefix_array <<< "$prefixes"
        local count=${#prefix_array[@]}

        if [[ $count -gt 1 && $count -lt 30 ]]; then
            for ((i=0; i<count; i++)); do
                for ((j=i+1; j<count; j++)); do
                    [[ -z "${prefix_array[$i]}" || -z "${prefix_array[$j]}" ]] && continue
                    echo "${prefix_array[$i]}-${prefix_array[$j]}.${domain}"
                    echo "${prefix_array[$j]}-${prefix_array[$i]}.${domain}"
                done
            done >> "$temp_permutations"
        fi
    fi

    # Remover duplicatas e domínios já conhecidos
    if [[ -s "$temp_permutations" ]]; then
        if [[ -s "$input_file" ]]; then
            sort -u "$temp_permutations" | grep -vxFf "$input_file" > "$output_file" 2>/dev/null || true
        else
            sort -u "$temp_permutations" > "$output_file"
        fi
    fi
    rm -f "$temp_permutations"

    local generated=$(wc -l < "$output_file" 2>/dev/null || echo 0)
    log_success "Geradas $generated permutações únicas"
}

# ============================================================================
# BRUTEFORCE DNS COM PUREDNS
# ============================================================================

bruteforce_dns() {
    local domain="$1"
    local output_file="$2"
    local wordlist="$3"
    local resolvers_file="${WORDLISTS_DIR}/resolvers.txt"

    # Verificar se puredns está instalado
    if ! command -v puredns &>/dev/null; then
        log_warning "puredns não encontrado. Instalando..."
        if command -v go &>/dev/null; then
            go install github.com/d3mondev/puredns/v2@latest 2>/dev/null
            export PATH="$PATH:$(go env GOPATH)/bin"
        fi

        if ! command -v puredns &>/dev/null; then
            log_error "Falha ao instalar puredns. Pulando bruteforce DNS."
            log_info "Instale manualmente: go install github.com/d3mondev/puredns/v2@latest"
            return 1
        fi
    fi

    # Criar/atualizar lista de resolvers
    if [[ ! -f "$resolvers_file" ]] || [[ $(find "$resolvers_file" -mtime +7 2>/dev/null) ]]; then
        log_info "Atualizando lista de resolvers DNS..."
        cat > "$resolvers_file" << 'RESOLVERS'
8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
9.9.9.9
149.112.112.112
208.67.222.222
208.67.220.220
64.6.64.6
64.6.65.6
77.88.8.8
77.88.8.1
94.140.14.14
94.140.15.15
RESOLVERS
    fi

    # Usar wordlist fornecida ou encontrar uma
    [[ -z "$wordlist" ]] && wordlist=$(find_dns_wordlist)

    log_info "Executando bruteforce DNS com puredns..."
    log_info "Wordlist: $(basename "$wordlist") ($(wc -l < "$wordlist") palavras)"

    # Executar puredns
    local temp_output=$(mktemp)

    if puredns bruteforce "$wordlist" "$domain" \
        -r "$resolvers_file" \
        -w "$temp_output" \
        --rate-limit 500 \
        -q 2>/dev/null; then

        # Mover resultados
        if [[ -s "$temp_output" ]]; then
            cat "$temp_output" >> "$output_file"
            sort -u "$output_file" -o "$output_file"
            local found=$(wc -l < "$temp_output")
            log_success "Bruteforce: $found novos subdomínios encontrados"
        else
            log_info "Nenhum novo subdomínio encontrado via bruteforce"
        fi
    else
        log_warning "puredns retornou erro (pode ser normal se não houver resultados)"
    fi

    rm -f "$temp_output"
}

# Resolver permutações com puredns
resolve_permutations() {
    local permutations_file="$1"
    local output_file="$2"
    local resolvers_file="${WORDLISTS_DIR}/resolvers.txt"

    [[ ! -s "$permutations_file" ]] && return 0

    if ! command -v puredns &>/dev/null; then
        log_warning "puredns não encontrado. Usando massdns/dig como fallback..."
        resolve_permutations_fallback "$permutations_file" "$output_file"
        return $?
    fi

    log_info "Resolvendo $(wc -l < "$permutations_file") permutações..."

    local temp_output=$(mktemp)

    if puredns resolve "$permutations_file" \
        -r "$resolvers_file" \
        -w "$temp_output" \
        --rate-limit 500 \
        -q 2>/dev/null; then

        if [[ -s "$temp_output" ]]; then
            cat "$temp_output" >> "$output_file"
            sort -u "$output_file" -o "$output_file"
            local found=$(wc -l < "$temp_output")
            log_success "Permutações: $found subdomínios válidos encontrados"
        fi
    fi

    rm -f "$temp_output"
}

# Fallback para resolver sem puredns
resolve_permutations_fallback() {
    local input_file="$1"
    local output_file="$2"
    local max_parallel=50

    log_info "Resolvendo permutações com dig (fallback)..."

    local temp_valid=$(mktemp)
    local count=0
    local total=$(wc -l < "$input_file")
    local resolve_start=$(date +%s)

    while IFS= read -r subdomain; do
        ((count++))
        if dig +short "$subdomain" @8.8.8.8 2>/dev/null | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
            echo "$subdomain" >> "$temp_valid"
        fi

        # Mostrar progresso
        if ((count % 50 == 0)) || [[ $count -eq $total ]]; then
            show_progress "$count" "$total" "Resolução DNS" "$resolve_start"
        fi
    done < "$input_file"

    echo ""

    if [[ -s "$temp_valid" ]]; then
        cat "$temp_valid" >> "$output_file"
        sort -u "$output_file" -o "$output_file"
        log_success "$(wc -l < "$temp_valid") subdomínios válidos encontrados"
    fi

    rm -f "$temp_valid"
}

# ============================================================================
# DESCOBERTA DE VARIAÇÕES DE TLD
# ============================================================================

# TLDs comuns para verificar
COMMON_TLDS=(
    "com" "net" "org" "io" "co" "dev" "app" "tech" "online" "site"
    "info" "biz" "me" "tv" "cc" "ws" "xyz" "club" "store" "shop"
    "gg" "ai" "cloud" "digital" "global" "pro" "live" "games"
    "com.br" "net.br" "org.br" "co.uk" "de" "fr" "es" "it" "nl" "eu"
)

# Descobrir variações de TLD que existem (DNS resolve)
discover_tld_variations() {
    local domain="$1"
    local output_file="$2"

    # Extrair nome base (sem TLD)
    local base_name=$(echo "$domain" | sed -E 's/\.[^.]+$//')
    # Se ainda tem ponto (ex: furia.com.br -> furia.com), extrair mais
    if [[ "$base_name" == *"."* ]]; then
        # Verificar se é TLD composto (com.br, co.uk, etc)
        local possible_tld=$(echo "$domain" | grep -oE '\.[^.]+\.[^.]+$' | sed 's/^\.//')
        if echo "${COMMON_TLDS[@]}" | grep -qw "$possible_tld"; then
            base_name=$(echo "$domain" | sed -E "s/\.${possible_tld//./\\.}$//")
        else
            base_name=$(echo "$domain" | cut -d. -f1)
        fi
    fi

    local current_tld=$(echo "$domain" | sed "s/^${base_name}\.//")

    log_info "Buscando variações de TLD para: ${YELLOW}${base_name}${NC} (atual: .${current_tld})"

    local found=0
    local temp_file=$(mktemp)

    echo -n "  Verificando TLDs: "
    for tld in "${COMMON_TLDS[@]}"; do
        # Pular o TLD atual
        [[ "$tld" == "$current_tld" ]] && continue

        local test_domain="${base_name}.${tld}"

        # Verificar se o domínio resolve (DNS) - rápido
        if timeout 2 dig +short "$test_domain" @8.8.8.8 2>/dev/null | grep -qE '^[0-9]+\.|^[a-f0-9:]+'; then
            echo "$test_domain" >> "$temp_file"
            ((found++))
            echo -ne "${GREEN}.${tld}${NC} "
        fi
    done

    echo ""
    echo ""

    if [[ $found -gt 0 ]]; then
        sort -u "$temp_file" > "$output_file"
        log_success "Encontradas $found variações de TLD que resolvem DNS"
        echo ""
        cat "$output_file" | while read -r d; do
            echo -e "    ${BLUE}•${NC} $d"
        done
    else
        touch "$output_file"
        log_info "Nenhuma variação de TLD encontrada"
    fi

    rm -f "$temp_file"
}

# ============================================================================
# VALIDAÇÃO DE PROPRIEDADE DE DOMÍNIO
# ============================================================================

# Verificar se whois está disponível
WHOIS_AVAILABLE=false
command -v whois &>/dev/null && WHOIS_AVAILABLE=true

# Extrair nameservers via dig (fallback quando whois não disponível)
get_nameservers() {
    local domain="$1"
    dig NS "$domain" +short 2>/dev/null | head -3 | tr '[:upper:]' '[:lower:]' | sort | tr '\n' '|' | sed 's/|$//'
}

# Extrair informações WHOIS relevantes
get_whois_fingerprint() {
    local domain="$1"

    if ! $WHOIS_AVAILABLE; then
        # Fallback: usar apenas nameservers via dig
        local ns=$(get_nameservers "$domain")
        echo "||${ns}"
        return
    fi

    local whois_data=$(timeout 10 whois "$domain" 2>/dev/null | head -100)

    # Extrair campos relevantes (normalizar para lowercase)
    local org=$(echo "$whois_data" | grep -iE "^(Registrant Organization|Organization|Org Name|org-name):" | head -1 | cut -d: -f2- | xargs 2>/dev/null | tr '[:upper:]' '[:lower:]')
    local email=$(echo "$whois_data" | grep -iE "^(Registrant Email|Admin Email|Tech Email):" | head -1 | cut -d: -f2- | xargs 2>/dev/null | tr '[:upper:]' '[:lower:]' | sed 's/@.*//')
    local ns=$(echo "$whois_data" | grep -iE "^Name Server:" | head -1 | cut -d: -f2- | xargs 2>/dev/null | tr '[:upper:]' '[:lower:]' | sed 's/\..*//')

    # Se não pegou NS do whois, usar dig
    [[ -z "$ns" ]] && ns=$(get_nameservers "$domain" | cut -d'|' -f1 | sed 's/\..*//')

    echo "${org}|${email}|${ns}"
}

# Extrair organização do certificado SSL
get_ssl_org() {
    local domain="$1"
    local ssl_org=$(echo | timeout 5 openssl s_client -connect "${domain}:443" -servername "$domain" 2>/dev/null | \
        openssl x509 -noout -subject 2>/dev/null | \
        grep -oP 'O = \K[^,/]+' | tr '[:upper:]' '[:lower:]')
    echo "$ssl_org"
}

# Verificar se domínio redireciona para o domínio principal
check_redirect_to_main() {
    local domain="$1"
    local main_domain="$2"

    # Verificar redirect HTTPS
    local final_url=$(curl -s -o /dev/null -w "%{url_effective}" -L --max-redirs 5 --max-time 8 "https://${domain}" 2>/dev/null)
    if echo "$final_url" | grep -qi "$main_domain"; then
        return 0
    fi

    # Verificar redirect HTTP
    final_url=$(curl -s -o /dev/null -w "%{url_effective}" -L --max-redirs 5 --max-time 8 "http://${domain}" 2>/dev/null)
    if echo "$final_url" | grep -qi "$main_domain"; then
        return 0
    fi

    return 1
}

# Verificar se o conteúdo da página menciona a marca/empresa
check_brand_in_content() {
    local domain="$1"
    local brand="$2"

    local content=$(curl -s --max-time 8 "https://${domain}" 2>/dev/null | head -c 50000)

    # Verificar título e meta tags
    if echo "$content" | grep -qi "<title>.*${brand}.*</title>"; then
        return 0
    fi

    # Verificar menções da marca no conteúdo
    local mentions=$(echo "$content" | grep -oi "$brand" | wc -l)
    if [[ $mentions -ge 3 ]]; then
        return 0
    fi

    return 1
}

# Comparar nameservers entre domínios
compare_nameservers() {
    local ns1="$1"
    local ns2="$2"

    [[ -z "$ns1" || -z "$ns2" ]] && return 1

    # Extrair provider do NS (cloudflare, aws, google, etc)
    local provider1=$(echo "$ns1" | grep -oE '(cloudflare|awsdns|google|azure|ns[0-9]*\.[a-z]+)' | head -1)
    local provider2=$(echo "$ns2" | grep -oE '(cloudflare|awsdns|google|azure|ns[0-9]*\.[a-z]+)' | head -1)

    if [[ -n "$provider1" && "$provider1" == "$provider2" ]]; then
        return 0
    fi

    # Comparar NS direto
    if [[ "$ns1" == "$ns2" ]]; then
        return 0
    fi

    return 1
}

# Validar se um domínio TLD pertence à mesma organização
validate_tld_ownership() {
    local tld_domain="$1"
    local main_domain="$2"
    local main_fingerprint="$3"
    local brand_name="$4"

    local score=0
    local reasons=""

    # Extrair partes do fingerprint principal
    local main_org=$(echo "$main_fingerprint" | cut -d'|' -f1)
    local main_email=$(echo "$main_fingerprint" | cut -d'|' -f2)
    local main_ns=$(echo "$main_fingerprint" | cut -d'|' -f3)

    # 1. Verificar redirect (MAIS CONFIÁVEL - verificar primeiro)
    if check_redirect_to_main "$tld_domain" "$main_domain"; then
        ((score += 60))
        reasons+="redirects "
    fi

    # 2. Verificar se menciona a marca no conteúdo
    if check_brand_in_content "$tld_domain" "$brand_name"; then
        ((score += 35))
        reasons+="brand_content "
    fi

    # 3. Comparar nameservers via dig (funciona sem whois)
    local main_ns_full=$(get_nameservers "$main_domain")
    local tld_ns_full=$(get_nameservers "$tld_domain")

    if compare_nameservers "$main_ns_full" "$tld_ns_full"; then
        ((score += 30))
        reasons+="ns_match "
    fi

    # 4. Verificar SSL (peso médio)
    local main_ssl=$(get_ssl_org "$main_domain")
    local tld_ssl=$(get_ssl_org "$tld_domain")

    if [[ -n "$main_ssl" && -n "$tld_ssl" ]]; then
        if [[ "$main_ssl" == "$tld_ssl" ]]; then
            ((score += 30))
            reasons+="ssl_match "
        fi
    fi

    # 5. Se WHOIS disponível, verificar também
    if $WHOIS_AVAILABLE; then
        local tld_fingerprint=$(get_whois_fingerprint "$tld_domain")
        local tld_org=$(echo "$tld_fingerprint" | cut -d'|' -f1)
        local tld_email=$(echo "$tld_fingerprint" | cut -d'|' -f2)

        # Comparar organização
        if [[ -n "$main_org" && -n "$tld_org" && "$main_org" != "redacted" && "$tld_org" != "redacted" ]]; then
            if [[ "$main_org" == "$tld_org" ]]; then
                ((score += 40))
                reasons+="org_match "
            fi
        fi

        # Comparar email prefix
        if [[ -n "$main_email" && -n "$tld_email" && "$main_email" != "redacted" ]]; then
            if [[ "$main_email" == "$tld_email" ]]; then
                ((score += 25))
                reasons+="email_match "
            fi
        fi
    fi

    # Retornar score e razões
    echo "${score}|${reasons}"
}

# Filtrar TLDs válidos (pertencem à mesma organização)
filter_valid_tlds() {
    local tld_file="$1"
    local main_domain="$2"
    local output_valid="$3"
    local output_invalid="$4"

    [[ ! -s "$tld_file" ]] && return 0

    # Extrair nome da marca (primeira parte do domínio)
    local brand_name=$(echo "$main_domain" | cut -d. -f1)

    log_info "Validando propriedade dos TLDs (marca: ${YELLOW}${brand_name}${NC})..."

    # Mostrar métodos disponíveis
    if $WHOIS_AVAILABLE; then
        echo -e "  ${GREEN}✓${NC} WHOIS disponível"
    else
        echo -e "  ${YELLOW}!${NC} WHOIS não instalado - usando métodos alternativos"
    fi
    echo -e "  ${GREEN}✓${NC} Verificação: redirect, conteúdo, nameservers, SSL"
    echo ""

    # Obter fingerprint do domínio principal
    local main_fingerprint=$(get_whois_fingerprint "$main_domain")

    local total=$(wc -l < "$tld_file")
    local validated=0
    local rejected=0
    local count=0
    local whois_start=$(date +%s)

    > "$output_valid"
    > "$output_invalid"

    while IFS= read -r tld_domain; do
        [[ -z "$tld_domain" ]] && continue
        [[ "$tld_domain" == "$main_domain" ]] && continue

        ((count++))
        show_progress "$count" "$total" "WHOIS" "$whois_start"

        local result=$(validate_tld_ownership "$tld_domain" "$main_domain" "$main_fingerprint" "$brand_name")
        local score=$(echo "$result" | cut -d'|' -f1)
        local reasons=$(echo "$result" | cut -d'|' -f2)

        # Score >= 40 = provavelmente válido
        if [[ $score -ge 40 ]]; then
            echo "${tld_domain}|score:${score}|${reasons}" >> "$output_valid"
            ((validated++))
        else
            echo "${tld_domain}|score:${score}|${reasons}" >> "$output_invalid"
            ((rejected++))
        fi

    done < "$tld_file"

    echo ""
    echo -e "  ${GREEN}✓ Validados:${NC} $validated (score >= 40)"
    echo -e "  ${YELLOW}✗ Rejeitados:${NC} $rejected (provavelmente não pertencem à organização)"

    if [[ -s "$output_invalid" && $rejected -gt 0 ]]; then
        echo ""
        echo -e "  ${YELLOW}TLDs rejeitados (podem ser de outras empresas):${NC}"
        head -5 "$output_invalid" | while read -r line; do
            echo -e "    ${RED}•${NC} $line"
        done
        [[ $rejected -gt 5 ]] && echo -e "    ${YELLOW}... e mais $((rejected - 5))${NC}"
    fi
}

# ============================================================================
# DETECÇÃO DE WAF
# ============================================================================

# ── detect_cdn_waf(url) ─────────────────────────────────────────────────────
# Detecta CDN/WAF/Cloud via cdncheck (ProjectDiscovery).
# Fallback: headers HTTP + CNAME dig se cdncheck não estiver instalado.
#
# Return codes:
#   0  = Limpo (sem CDN/WAF/Cloud)
#   1  = Bloqueio ativo (challenge page)
#   2  = WAF detectado (provider no stdout)
#   3  = CDN detectado (provider no stdout)
#   4  = Cloud detectado (provider no stdout)
# ────────────────────────────────────────────────────────────────────────────
detect_cdn_waf() {
    local url="$1"
    local host
    host=$(echo "$url" | sed -E 's#^https?://##; s#[/:].*##')

    # ── Método primário: cdncheck ──
    if command -v cdncheck &>/dev/null; then
        local result
        result=$(echo "$host" | cdncheck -resp -silent -nc 2>/dev/null | head -1)

        if [[ -n "$result" ]]; then
            local detect_type provider
            detect_type=$(echo "$result" | grep -oP '\[\K[^\]]+' | head -1)
            provider=$(echo "$result" | grep -oP '\[\K[^\]]+' | tail -1)

            case "$detect_type" in
                waf)
                    echo "$provider"
                    return 2
                    ;;
                cdn)
                    echo "$provider"
                    return 3
                    ;;
                cloud)
                    echo "$provider"
                    return 4
                    ;;
            esac
        fi

        # cdncheck não detectou nada → verificar bloqueio ativo no body
        local body
        body=$(curl -s "$url" -H "User-Agent: Mozilla/5.0" --max-time 8 2>/dev/null | head -1000)
        if echo "$body" | grep -qi "just a moment\|checking your browser\|enable javascript\|challenge\|captcha"; then
            return 1
        fi

        return 0
    fi

    # ── Fallback: headers HTTP + CNAME dig ──
    local headers body waf_detected=""

    headers=$(curl -s -I "$url" -H "User-Agent: Mozilla/5.0" --max-time 10 2>/dev/null | head -30)
    body=$(curl -s "$url" -H "User-Agent: Mozilla/5.0" --max-time 10 2>/dev/null | head -1000)

    if echo "$headers" | grep -qi "cloudflare\|cf-ray\|cf-cache"; then
        waf_detected="cloudflare"
    elif echo "$headers" | grep -qi "awselb\|awsalb\|x-amz"; then
        waf_detected="aws-waf"
    elif echo "$headers" | grep -qi "akamai\|x-akamai"; then
        waf_detected="akamai"
    elif echo "$headers" | grep -qi "incapsula\|x-iinfo\|visid_incap"; then
        waf_detected="incapsula"
    elif echo "$headers" | grep -qi "sucuri\|x-sucuri"; then
        waf_detected="sucuri"
    elif echo "$headers" | grep -qi "barracuda"; then
        waf_detected="barracuda"
    elif echo "$headers" | grep -qi "f5\|bigip"; then
        waf_detected="f5-bigip"
    fi

    # Verificar página de bloqueio
    if echo "$body" | grep -qi "just a moment\|checking your browser\|enable javascript\|challenge\|captcha"; then
        log_error "BLOQUEIO ATIVO detectado! Aguardar ou usar VPN/proxy."
        return 1
    fi

    if [[ -n "$waf_detected" ]]; then
        echo "$waf_detected"
        return 2
    fi

    # Fallback CDN via CNAME dig
    local cname_out
    cname_out=$(dig +short CNAME "$host" 2>/dev/null | tr '[:upper:]' '[:lower:]')
    local cdn_patterns="cloudflare\|akamai\|fastly\|cloudfront\|incapsula\|sucuri\|edgecastcdn\|azureedge\|stackpath\|imperva\|cdn77\|keycdn\|limelight"
    if echo "$cname_out" | grep -qi "$cdn_patterns"; then
        echo "$(echo "$cname_out" | grep -i "$cdn_patterns" | head -1)"
        return 3
    fi

    return 0
}

# Aliases de compatibilidade (funções legadas apontam para a nova)
detect_waf() { detect_cdn_waf "$@"; }
check_cdn_dig() {
    local url="$1"
    detect_cdn_waf "$url" >/dev/null 2>&1
    local ret=$?
    [[ $ret -eq 3 ]] && return 1
    return 0
}

# ── bulk_cdn_check(input_file, out_clean, out_cdn, out_waf) ─────────────────
# Processa lista de URLs em massa via cdncheck.
# Separa em 3 arquivos: limpos, CDN/Cloud, WAF.
# Fallback: per-host detect_cdn_waf() se cdncheck não disponível.
# ────────────────────────────────────────────────────────────────────────────
bulk_cdn_check() {
    local input_file="$1"
    local out_clean="$2"
    local out_cdn="$3"
    local out_waf="$4"

    > "$out_clean"
    > "$out_cdn"
    > "$out_waf"

    local total
    total=$(wc -l < "$input_file" 2>/dev/null || echo 0)
    [[ $total -eq 0 ]] && return 0

    if command -v cdncheck &>/dev/null; then
        log_info "cdncheck: analisando ${total} hosts em massa..."

        # Extrair hostnames das URLs
        local hosts_tmp
        hosts_tmp=$(mktemp)
        sed -E 's#^https?://##; s#[/:].*##' "$input_file" | sort -u > "$hosts_tmp"

        # Rodar cdncheck: hosts detectados (CDN/WAF/Cloud)
        local detected_tmp
        detected_tmp=$(mktemp)
        cdncheck -i "$hosts_tmp" -resp -silent -nc 2>/dev/null > "$detected_tmp"

        # Construir mapa host → tipo|provider
        declare -A cdn_map
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local h t p
            h=$(echo "$line" | awk '{print $1}')
            t=$(echo "$line" | grep -oP '\[\K[^\]]+' | head -1)
            p=$(echo "$line" | grep -oP '\[\K[^\]]+' | tail -1)
            cdn_map["$h"]="${t}|${p}"
        done < "$detected_tmp"

        # Classificar cada URL original
        local current=0
        local waf_count=0 cdn_count=0 clean_count=0
        while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            ((current++))
            show_progress "$current" "$total" "CDN/WAF Check (cdncheck)"

            local host
            host=$(echo "$url" | sed -E 's#^https?://##; s#[/:].*##')
            local info="${cdn_map[$host]:-}"

            if [[ -z "$info" ]]; then
                echo "$url" >> "$out_clean"
                ((clean_count++))
            else
                local dtype="${info%%|*}"
                local dprov="${info##*|}"
                case "$dtype" in
                    waf)
                        echo "${url} [WAF: ${dprov}]" >> "$out_waf"
                        ((waf_count++))
                        ;;
                    cdn|cloud)
                        echo "${url} [${dtype^^}: ${dprov}]" >> "$out_cdn"
                        ((cdn_count++))
                        ;;
                    *)
                        echo "${url} [${dtype}: ${dprov}]" >> "$out_cdn"
                        ((cdn_count++))
                        ;;
                esac
            fi
        done < "$input_file"

        rm -f "$hosts_tmp" "$detected_tmp"

        echo ""
        log_success "cdncheck: ${GREEN}${clean_count} limpos${NC}, ${YELLOW}${waf_count} WAF${NC}, ${BLUE}${cdn_count} CDN/Cloud${NC}"
    else
        # Fallback: per-host (mais lento)
        log_warning "cdncheck não instalado — usando detecção manual (mais lento)"
        log_info "Instale com: go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"

        local current=0
        local waf_count=0 cdn_count=0 clean_count=0
        while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            ((current++))
            show_progress "$current" "$total" "WAF/CDN Detection (fallback)"

            local provider
            provider=$(detect_cdn_waf "$url" 2>/dev/null)
            local ret=$?

            case $ret in
                0) echo "$url" >> "$out_clean"; ((clean_count++)) ;;
                1) ((waf_count++)) ;;  # Bloqueio ativo — não adicionar a nenhum
                2) echo "${url} [WAF: ${provider}]" >> "$out_waf"; ((waf_count++)) ;;
                3) echo "${url} [CDN: ${provider}]" >> "$out_cdn"; ((cdn_count++)) ;;
                4) echo "${url} [CLOUD: ${provider}]" >> "$out_cdn"; ((cdn_count++)) ;;
            esac
        done < "$input_file"

        echo ""
        log_success "Detecção: ${GREEN}${clean_count} limpos${NC}, ${YELLOW}${waf_count} WAF${NC}, ${BLUE}${cdn_count} CDN/Cloud${NC}"
    fi
}

# ============================================================================
# TRIAGE HOSTS (para hunt mode)
# ============================================================================

triage_hosts() {
    local alive_details="$1"
    local recon_dir="$2"

    local targets_200ok="${recon_dir}/targets_200ok.txt"
    local targets_interesting="${recon_dir}/targets_interesting.txt"
    local targets_no_waf="${recon_dir}/targets_no_waf.txt"
    local targets_waf="${recon_dir}/targets_waf.txt"
    local targets_cdn="${recon_dir}/targets_cdn.txt"

    # Limpar arquivos anteriores
    > "$targets_200ok"
    > "$targets_interesting"
    > "$targets_no_waf"
    > "$targets_waf"
    > "$targets_cdn"

    # Parse httpx output: extrair hosts por status code
    # Formato httpx: URL [STATUS] [SIZE] [TITLE] [TECH]
    while IFS= read -r line; do
        local url status
        url=$(echo "$line" | awk '{print $1}')
        status=$(echo "$line" | grep -oP '\[\K[0-9]+(?=\])' | head -1)

        [[ -z "$url" || -z "$status" ]] && continue

        case "$status" in
            200)
                echo "$url" >> "$targets_200ok"
                ;;
            301|302|307|308|401|403)
                echo "${url} [${status}]" >> "$targets_interesting"
                ;;
        esac
    done < "$alive_details"

    local count_200=$(wc -l < "$targets_200ok" 2>/dev/null || echo 0)
    local count_interesting=$(wc -l < "$targets_interesting" 2>/dev/null || echo 0)

    log_success "${count_200} hosts com 200 OK"
    [[ $count_interesting -gt 0 ]] && log_info "${count_interesting} hosts com status interessante (301/401/403)"

    if [[ $count_200 -eq 0 ]]; then
        log_warning "Nenhum host com 200 OK encontrado!"
        echo "0"
        return 0
    fi

    # WAF/CDN detection em massa via cdncheck (ou fallback)
    echo ""
    log_info "Detectando WAF/CDN nos ${count_200} hosts com 200 OK..."
    echo ""

    bulk_cdn_check "$targets_200ok" "$targets_no_waf" "$targets_cdn" "$targets_waf"

    local no_waf_count=$(wc -l < "$targets_no_waf" 2>/dev/null || echo 0)
    local waf_count=$(wc -l < "$targets_waf" 2>/dev/null || echo 0)
    local cdn_count=$(wc -l < "$targets_cdn" 2>/dev/null || echo 0)

    echo ""

    # Triage summary box
    draw_line "top"
    box_center "${BOLD}TRIAGE SUMMARY${NC}"
    draw_line "mid"
    box_left "${GREEN}200 OK Total:${NC}         ${count_200} hosts"
    draw_line "sep"
    box_left "${GREEN}✓ No WAF/CDN:${NC}         ${BOLD}${GREEN}${no_waf_count}${NC} (prime targets)"
    box_left "${YELLOW}⚠ WAF Detected:${NC}       ${waf_count} hosts"
    box_left "${BLUE}☁ CDN Detected:${NC}       ${cdn_count} hosts"
    draw_line "sep"
    box_left "${CYAN}Interesting (non-200):${NC} ${count_interesting} hosts"
    draw_line "bot"
    echo ""

    # Retornar count de no-WAF targets
    echo "$no_waf_count"
}

# ============================================================================
# HUNT MODE - 200 OK + No WAF → Deep Scan
# ============================================================================

hunt_recon() {
    local domain="$1"
    local wordlist="$2"
    local threads="${3:-60}"
    local rate="${4:-100}"

    if [[ -z "$domain" ]]; then
        log_error "Uso: ./ffuf_master.sh --hunt <dominio> [wordlist] [threads] [rate]"
        echo ""
        echo "Hunt Mode: Encontra ativos esquecidos (200 OK + sem WAF) e faz deep scan"
        echo ""
        echo "Exemplos:"
        echo "  ./ffuf_master.sh --hunt target.com"
        echo "  ./ffuf_master.sh --hunt target.com /path/to/wordlist.txt"
        echo "  ./ffuf_master.sh --hunt target.com auto 80 150"
        return 1
    fi

    # Remover protocolo se incluído
    domain=$(echo "$domain" | sed -E 's#^https?://##; s#/$##')

    # Encontrar wordlist
    wordlist=$(find_wordlist "$wordlist") || return 1

    # Criar diretório de resultados
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local recon_dir="${RESULTS_DIR}/${domain}_hunt_${timestamp}"
    mkdir -p "${recon_dir}/scans"

    echo ""
    draw_line "top"
    box_center "${BOLD}${RED}🎯 HUNT MODE${NC} ${BOLD}- FFUF MASTER v${SCRIPT_VERSION}${NC}"
    box_center "${RED}@${GREEN}ofj${YELLOW}aaah${NC}"
    draw_line "mid"
    box_left "Target:   ${YELLOW}${domain}${NC}"
    box_left "Strategy: ${RED}200 OK${NC} + ${GREEN}No WAF${NC} → ${BOLD}Deep Scan${NC}"
    box_left "Threads:  ${threads} | Rate: ${rate}/s (aggressive, no WAF)"
    box_left "Wordlist: $(basename "$wordlist") ($(wc -l < "$wordlist") palavras)"
    box_left "Output:   ${recon_dir}"
    draw_line "bot"
    echo ""

    # ===========================================================
    # PHASE 1: DISCOVERY (subdomain enumeration)
    # ===========================================================
    log_phase "PHASE 1: SUBDOMAIN DISCOVERY" "1" "6"

    local subdomains_file="${recon_dir}/subdomains.txt"
    local subfinder_file="${recon_dir}/subfinder.txt"
    local tldfinder_file="${recon_dir}/tldfinder.txt"
    local subfinder_count=0
    local tldfinder_count=0

    # Executar subfinder
    log_info "Executando subfinder em ${domain}..."
    if command -v subfinder &>/dev/null; then
        subfinder -d "$domain" -all -recursive -silent 2>/dev/null | sort -u > "$subfinder_file"
        subfinder_count=$(wc -l < "$subfinder_file" 2>/dev/null || echo 0)
        log_success "subfinder: ${GREEN}${subfinder_count}${NC} subdomínios"
    else
        log_warning "subfinder não encontrado!"
        touch "$subfinder_file"
    fi

    # Descobrir variações de TLD
    local tld_raw="${recon_dir}/tld_variations_raw.txt"
    local tld_valid="${recon_dir}/tld_variations_valid.txt"
    local tld_invalid="${recon_dir}/tld_variations_invalid.txt"
    local tld_validated=0

    echo ""
    log_info "Buscando variações de TLD do domínio..."

    if command -v tldfinder &>/dev/null; then
        tldfinder -d "$domain" -silent 2>/dev/null | sort -u > "${recon_dir}/tldfinder_private.txt"
        local private_count=$(wc -l < "${recon_dir}/tldfinder_private.txt" 2>/dev/null || echo 0)
        if [[ $private_count -gt 0 ]]; then
            log_success "tldfinder: ${GREEN}${private_count}${NC} TLDs privados"
            cat "${recon_dir}/tldfinder_private.txt" >> "$tld_raw"
        fi
    fi

    discover_tld_variations "$domain" "${recon_dir}/tld_common.txt"
    cat "${recon_dir}/tld_common.txt" >> "$tld_raw" 2>/dev/null
    sort -u "$tld_raw" -o "$tld_raw" 2>/dev/null

    tldfinder_count=$(wc -l < "$tld_raw" 2>/dev/null || echo 0)

    if [[ $tldfinder_count -gt 0 ]]; then
        echo ""
        log_info "Validando propriedade das variações de TLD..."
        filter_valid_tlds "$tld_raw" "$domain" "$tld_valid" "$tld_invalid"
        tld_validated=$(wc -l < "$tld_valid" 2>/dev/null || echo 0)
        cut -d'|' -f1 "$tld_valid" > "$tldfinder_file" 2>/dev/null

        if [[ $tld_validated -gt 0 ]]; then
            echo ""
            local brand_name_display=$(echo "$domain" | cut -d. -f1 | tr '[:lower:]' '[:upper:]')
            echo -e "  ${GREEN}TLDs validados (pertencem à ${brand_name_display}):${NC}"
            cat "$tld_valid" | while IFS='|' read -r tld_dom score reasons; do
                echo -e "    ${GREEN}✓${NC} $tld_dom (${score}, ${reasons})"
            done
        fi
    else
        touch "$tldfinder_file"
        touch "$tld_raw"
    fi

    # Combinar resultados únicos
    cat "$subfinder_file" "$tldfinder_file" 2>/dev/null | sort -u > "$subdomains_file"
    echo "$domain" >> "$subdomains_file"
    sort -u "$subdomains_file" -o "$subdomains_file"
    local total_subs=$(wc -l < "$subdomains_file")

    echo ""
    log_success "Total subdomínios encontrados: ${GREEN}${total_subs}${NC}"

    # PHASE 1.5: Permutation + DNS bruteforce
    log_phase "PHASE 1.5: ACTIVE DISCOVERY (permutation + bruteforce)" "2" "6"

    local permutations_file="${recon_dir}/permutations.txt"
    local all_subs_file="${recon_dir}/all_subdomains.txt"
    cp "$subdomains_file" "$all_subs_file"

    log_info "Gerando permutações dos subdomínios..."
    permute_subdomains "$subdomains_file" "$domain" "$permutations_file"

    if [[ -s "$permutations_file" ]]; then
        local perm_count=$(wc -l < "$permutations_file")
        log_info "Resolvendo $perm_count permutações..."
        resolve_permutations "$permutations_file" "$all_subs_file"
    fi

    log_info "Iniciando bruteforce DNS..."
    bruteforce_dns "$domain" "$all_subs_file"

    sort -u "$all_subs_file" -o "$subdomains_file"
    local new_total=$(wc -l < "$subdomains_file")
    local discovered=$((new_total - total_subs))

    if [[ $discovered -gt 0 ]]; then
        log_success "Descobertos $discovered novos subdomínios via permutação/bruteforce!"
    fi
    total_subs=$new_total

    # ===========================================================
    # PHASE 2: PROBING (httpx with extended flags)
    # ===========================================================
    log_phase "PHASE 2: PROBING HOSTS (httpx extended)" "3" "6"

    local alive_file="${recon_dir}/alive.txt"
    local alive_details="${recon_dir}/alive_details.txt"

    log_info "Verificando quais subdomínios estão ativos (extended mode)..."

    if command -v httpx &>/dev/null; then
        start_spinner "Executando httpx com detecção de tecnologia..."
        cat "$subdomains_file" | httpx -silent -timeout 10 -retries 2 \
            -status-code -content-length -title -tech-detect -no-fallback \
            -o "$alive_details" 2>/dev/null
        stop_spinner

        # Extrair apenas URLs
        cat "$alive_details" | awk '{print $1}' | sort -u > "$alive_file"
    else
        log_error "httpx não encontrado! Instale com: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
        while read -r sub; do
            for proto in https http; do
                if curl -s -o /dev/null -w "%{http_code}" "${proto}://${sub}" --max-time 5 2>/dev/null | grep -q "^[23]"; then
                    echo "${proto}://${sub}" >> "$alive_file"
                    echo "${proto}://${sub} [200]" >> "$alive_details"
                    break
                fi
            done
        done < "$subdomains_file"
    fi

    local total_alive=$(wc -l < "$alive_file" 2>/dev/null || echo "0")
    log_success "$total_alive hosts ativos"

    if [[ "$total_alive" -eq 0 ]]; then
        log_error "Nenhum host ativo encontrado!"
        return 1
    fi

    # Mostrar hosts ativos com detalhes
    echo ""
    if [[ -f "$alive_details" ]]; then
        head -15 "$alive_details" | while read -r line; do
            echo -e "  ${GREEN}✓${NC} $line"
        done
    fi
    [[ $total_alive -gt 15 ]] && echo -e "  ${YELLOW}... e mais $((total_alive - 15)) hosts${NC}"

    # ===========================================================
    # PHASE 3: TRIAGE (200 OK + WAF/CDN detection)
    # ===========================================================
    log_phase "PHASE 3: TRIAGE (200 OK + WAF/CDN filter)" "4" "6"

    # triage_hosts retorna count na última linha de stdout
    local triage_output
    triage_output=$(triage_hosts "$alive_details" "$recon_dir")
    local no_waf_count
    no_waf_count=$(echo "$triage_output" | tail -1)

    local targets_no_waf="${recon_dir}/targets_no_waf.txt"
    local targets_waf="${recon_dir}/targets_waf.txt"
    local targets_cdn="${recon_dir}/targets_cdn.txt"
    local targets_200ok="${recon_dir}/targets_200ok.txt"
    local targets_interesting="${recon_dir}/targets_interesting.txt"

    if [[ "$no_waf_count" -eq 0 || ! -s "$targets_no_waf" ]]; then
        log_warning "Nenhum target sem WAF/CDN encontrado."
        log_info "Todos os 200 OK estão protegidos. Verifique targets_waf.txt para análise manual."
    fi

    # Mostrar targets prime
    if [[ -s "$targets_no_waf" ]]; then
        echo ""
        log_success "Prime targets (200 OK, No WAF, No CDN):"
        while read -r url; do
            echo -e "  ${GREEN}🎯${NC} ${BOLD}${url}${NC}"
        done < "$targets_no_waf"
        echo ""
    fi

    # ===========================================================
    # PHASE 4: DEEP SCAN (no-WAF targets only)
    # ===========================================================
    log_phase "PHASE 4: DEEP SCAN (unprotected targets)" "5" "6"

    if [[ ! -s "$targets_no_waf" ]]; then
        log_warning "Nenhum target para deep scan (todos protegidos por WAF/CDN)."
        log_info "Pulando para consolidação..."
    else
        local scan_dir="${recon_dir}/scans"
        local target_count
        target_count=$(wc -l < "$targets_no_waf")

        # --- 4a: Disclosure check em todos os no-WAF targets ---
        echo ""
        log_info "${BOLD}[4a] Verificação de Information Disclosure${NC}"
        echo ""

        local disclosure_count=0
        local disc_current=0

        while IFS= read -r url; do
            ((disc_current++))
            echo -e "  ${CYAN}[${disc_current}/${target_count}]${NC} Disclosure check: ${YELLOW}${url}${NC}"
            check_disclosure "$url" 2>/dev/null
            echo ""
        done < "$targets_no_waf"

        # --- 4b: Aggressive ffuf content discovery ---
        echo ""
        log_info "${BOLD}[4b] Aggressive Content Discovery (ffuf)${NC}"
        echo ""
        log_info "Config: ${GREEN}${threads} threads${NC}, ${GREEN}${rate} req/s${NC} (aggressive - no WAF)"

        # Preparar wordlists
        create_api_wordlist 2>/dev/null
        local api_wordlist="${WORDLISTS_DIR}/api-master.txt"

        local progress_file="${scan_dir}/.progress"
        echo "0" > "$progress_file"

        # process_host function (inline, same pattern as full_recon)
        process_host() {
            local url="$1"
            local scan_dir="$2"
            local default_wordlist="$3"
            local job_threads="$4"
            local job_rate="$5"
            local timeout_val="$6"
            local maxtime="$7"
            local recursion_depth="$8"
            local total="$9"
            local progress_file="${10}"
            local api_wordlist="${11}"
            local wordlists_dir="${12}"

            local clean_name=$(echo "$url" | sed -E 's#^https?://##; s#[/:.]#_#g')
            local output_file="${scan_dir}/${clean_name}.json"
            local log_file="${scan_dir}/${clean_name}.log"

            # Incrementar progresso
            local current
            if command -v flock &>/dev/null; then
                current=$(flock -x "$progress_file" bash -c 'c=$(<"$1"); echo $((c + 1)) > "$1"; echo $((c + 1))' _ "$progress_file")
            else
                current=$(cat "$progress_file" 2>/dev/null || echo 0)
                echo $((current + 1)) > "$progress_file"
                current=$((current + 1))
            fi

            # Detectar contexto API
            local subdomain=$(echo "$url" | sed -E 's#^https?://##; s#/.*##; s#:[0-9]+##')
            local path=$(echo "$url" | grep -oE '/[^?#]*' | head -1)
            local is_api=false
            local wordlist="$default_wordlist"
            local context_msg=""

            if echo "$subdomain" | grep -qiE '^(api[0-9]*|api-|apis|gateway|gw|graphql|rest|v[0-9]+|dev[0-9]*|stg|staging|prod|uat|qa|test|sandbox|internal)[-.]'; then
                is_api=true
            elif echo "$subdomain" | grep -qiE '(dev|stg|staging|prod|uat|qa|test)[-.]?api'; then
                is_api=true
            elif echo "$path" | grep -qiE '^/(api|apis|v[0-9]+|graphql|rest)/'; then
                is_api=true
            fi

            if $is_api && [[ -f "$api_wordlist" ]]; then
                wordlist="$api_wordlist"
                context_msg=" [API]"
            fi

            local wl_name=$(basename "$wordlist")
            echo -e "\033[0;36m[${current}/${total}]\033[0m \033[1;33m${url}\033[0m${context_msg} → ${wl_name}"

            # Calibrar target
            local calibration_flags
            calibration_flags=$(calibrate_target "$url" 3)
            if [[ -n "$calibration_flags" ]]; then
                echo -e "  \033[0;33m⚠ Catch-all detectado → filtro: ${calibration_flags}\033[0m"
            fi

            # Executar FFUF (aggressive - no WAF)
            if timeout $((maxtime + 30)) ffuf -c \
                -u "${url}/FUZZ" \
                -w "$wordlist" \
                -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
                -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
                -t "$job_threads" \
                -rate "$job_rate" \
                -timeout "$timeout_val" \
                -recursion \
                -recursion-depth "$recursion_depth" \
                -mc 200,201,204,301,302,307,308,401,403,405,500 \
                -fc 404 \
                -ac \
                $calibration_flags \
                -maxtime "$maxtime" \
                -maxtime-job 120 \
                -se \
                -sf \
                -o "$output_file" \
                -of json \
                > "$log_file" 2>&1; then

                local results=$(python3 -c "import json; print(len(json.load(open('$output_file')).get('results', [])))" 2>/dev/null || echo "0")
                if [[ "$results" -gt 0 ]]; then
                    echo -e "  \033[0;32m✓ $results resultados - ${url}\033[0m"
                fi
            else
                echo -e "  \033[0;31m✗ Timeout/Erro - ${url}\033[0m"
            fi
        }
        export -f calibrate_target
        export -f process_host

        # Calcular paralelismo
        local cpu_cores=$(nproc 2>/dev/null || echo 4)
        local mem_gb=$(free -g 2>/dev/null | awk '/^Mem:/{print $7}' || echo 4)
        local max_parallel=$((cpu_cores / 2))
        [[ $max_parallel -lt 2 ]] && max_parallel=2
        [[ $max_parallel -gt 6 ]] && max_parallel=6
        [[ $max_parallel -gt $target_count ]] && max_parallel=$target_count
        [[ $mem_gb -lt $max_parallel ]] && max_parallel=$mem_gb
        [[ $max_parallel -lt 1 ]] && max_parallel=1

        local job_threads=$((threads / max_parallel))
        local job_rate=$((rate / max_parallel))
        [[ $job_threads -lt 5 ]] && job_threads=5
        [[ $job_rate -lt 10 ]] && job_rate=10

        log_info "Iniciando ffuf em ${target_count} targets sem WAF..."
        log_info "Config: ${GREEN}${max_parallel} jobs paralelos${NC}, ${job_threads} threads/job, ${job_rate} req/s/job"
        echo ""

        if command -v parallel &>/dev/null; then
            cat "$targets_no_waf" | parallel -j "$max_parallel" --line-buffer \
                process_host {} "$scan_dir" "$wordlist" "$job_threads" "$job_rate" \
                "$DEFAULT_TIMEOUT" "$DEFAULT_MAXTIME" "$DEFAULT_RECURSION_DEPTH" \
                "$target_count" "$progress_file" "$api_wordlist" "$WORDLISTS_DIR"
        else
            cat "$targets_no_waf" | xargs -P "$max_parallel" -I {} bash -c \
                'process_host "$@"' _ {} "$scan_dir" "$wordlist" "$job_threads" "$job_rate" \
                "$DEFAULT_TIMEOUT" "$DEFAULT_MAXTIME" "$DEFAULT_RECURSION_DEPTH" \
                "$target_count" "$progress_file" "$api_wordlist" "$WORDLISTS_DIR"
        fi

        # Filter false positives
        log_info "Filtrando falsos positivos dos resultados..."
        for json_file in "${scan_dir}"/*.json; do
            [[ -f "$json_file" ]] || continue
            local raw_count=$(python3 -c "import json; print(len(json.load(open('$json_file')).get('results', [])))" 2>/dev/null || echo "0")
            if [[ "$raw_count" -gt 0 ]]; then
                filter_results "$json_file" >/dev/null 2>&1
                local filtered_file="${json_file%.json}_filtered.json"
                if [[ -f "$filtered_file" ]]; then
                    cp "$filtered_file" "$json_file"
                    rm -f "$filtered_file"
                fi
            fi
        done

        # --- 4c: API enumeration on API-context subdomains ---
        echo ""
        log_info "${BOLD}[4c] API Enumeration (API-context subdomains)${NC}"
        echo ""

        local api_scanned=0
        while IFS= read -r url; do
            local subdomain=$(echo "$url" | sed -E 's#^https?://##; s#/.*##; s#:[0-9]+##')
            if echo "$subdomain" | grep -qiE '^(api[0-9]*|api-|apis|gateway|gw|graphql|rest|v[0-9]+)[-.]'; then
                log_info "API scan: ${YELLOW}${url}${NC}"
                enum_api "$url" 2>/dev/null
                ((api_scanned++))
            fi
        done < "$targets_no_waf"

        if [[ $api_scanned -eq 0 ]]; then
            log_info "Nenhum subdomínio com contexto de API encontrado."
        fi
    fi

    # ===========================================================
    # PHASE 5: WAF TARGETS (listing only)
    # ===========================================================
    log_phase "PHASE 5: WAF/CDN TARGETS (report only)" "5" "6"

    if [[ -s "$targets_waf" ]]; then
        echo ""
        log_warning "Hosts protegidos por WAF (scan não realizado):"
        while IFS= read -r line; do
            echo -e "  ${YELLOW}🛡${NC} ${line}"
        done < "$targets_waf"
    fi

    if [[ -s "$targets_cdn" ]]; then
        echo ""
        log_info "Hosts atrás de CDN:"
        while IFS= read -r line; do
            echo -e "  ${BLUE}☁${NC} ${line}"
        done < "$targets_cdn"
    fi

    if [[ ! -s "$targets_waf" && ! -s "$targets_cdn" ]]; then
        log_info "Nenhum host protegido por WAF/CDN detectado."
    fi

    # ===========================================================
    # PHASE 6: CONSOLIDATION + REPORT
    # ===========================================================
    log_phase "PHASE 6: CONSOLIDATION + REPORT" "6" "6"

    local report_file="${recon_dir}/REPORT.md"

    # Contagem de resultados
    local total_findings=0
    local scan_dir="${recon_dir}/scans"
    local success=0

    for json_file in "${scan_dir}"/*.json; do
        [[ -f "$json_file" ]] || continue
        local count=$(python3 -c "import json; print(len(json.load(open('$json_file')).get('results', [])))" 2>/dev/null || echo "0")
        [[ "$count" -gt 0 ]] && { ((total_findings += count)); ((success++)); }
    done

    local count_200=$(wc -l < "$targets_200ok" 2>/dev/null || echo 0)
    local waf_count=$(wc -l < "$targets_waf" 2>/dev/null || echo 0)
    local cdn_count=$(wc -l < "$targets_cdn" 2>/dev/null || echo 0)
    local no_waf_final=$(wc -l < "$targets_no_waf" 2>/dev/null || echo 0)
    local interesting_count=$(wc -l < "$targets_interesting" 2>/dev/null || echo 0)

    # Generate REPORT.md
    cat > "$report_file" << REPORT_EOF
# Hunt Report - ${domain}

**Data:** $(date)
**Modo:** Hunt (200 OK + No WAF → Deep Scan)
**Versão:** FFUF Master v${SCRIPT_VERSION}

---

## Triage Summary

| Category | Count |
|----------|-------|
| Subdomínios descobertos | ${total_subs} |
| Hosts ativos | ${total_alive} |
| 200 OK | ${count_200} |
| **No WAF/CDN (prime)** | **${no_waf_final}** |
| WAF Detected | ${waf_count} |
| CDN Detected | ${cdn_count} |
| Interesting (non-200) | ${interesting_count} |

---

## Prime Targets (No WAF/CDN)

REPORT_EOF

    if [[ -s "$targets_no_waf" ]]; then
        while read -r url; do
            echo "- ${url}" >> "$report_file"
        done < "$targets_no_waf"
    else
        echo "_Nenhum target sem proteção encontrado._" >> "$report_file"
    fi

    echo "" >> "$report_file"

    # Disclosure findings section
    echo "---" >> "$report_file"
    echo "" >> "$report_file"
    echo "## Disclosure Findings" >> "$report_file"
    echo "" >> "$report_file"

    local disclosure_files_found=false
    for disc_file in "${RESULTS_DIR}"/disclosure_*.txt; do
        [[ -f "$disc_file" ]] || continue
        # Only include recent disclosure files (from this session)
        local disc_time
        disc_time=$(stat -c %Y "$disc_file" 2>/dev/null || echo 0)
        local session_start=$SCRIPT_START_TIME
        if [[ $disc_time -ge $session_start ]]; then
            disclosure_files_found=true
            echo "### $(basename "$disc_file")" >> "$report_file"
            echo '```' >> "$report_file"
            head -50 "$disc_file" >> "$report_file"
            echo '```' >> "$report_file"
            echo "" >> "$report_file"
        fi
    done

    if ! $disclosure_files_found; then
        echo "_Nenhum arquivo sensível encontrado via disclosure check._" >> "$report_file"
        echo "" >> "$report_file"
    fi

    # Ffuf findings per host
    echo "---" >> "$report_file"
    echo "" >> "$report_file"
    echo "## Content Discovery Findings" >> "$report_file"
    echo "" >> "$report_file"

    for json_file in "${scan_dir}"/*.json; do
        [[ -f "$json_file" ]] || continue

        local host=$(basename "$json_file" .json | sed 's/_/./g' | sed 's/^https\.\.//; s/^http\.\.//')
        local count=$(python3 -c "import json; print(len(json.load(open('$json_file')).get('results', [])))" 2>/dev/null || echo "0")

        if [[ "$count" -gt 0 ]]; then
            echo "### ${host} (${count} findings)" >> "$report_file"
            echo "" >> "$report_file"

            python3 -c "
import json
data = json.load(open('$json_file'))
for r in data.get('results', [])[:30]:
    url = r.get('url', '')
    status = r.get('status', 0)
    length = r.get('length', 0)
    print(f'- [{status}] {url} ({length} bytes)')
" 2>/dev/null >> "$report_file"

            echo "" >> "$report_file"
        fi
    done

    # WAF targets section
    echo "---" >> "$report_file"
    echo "" >> "$report_file"
    echo "## WAF/CDN Protected Hosts (manual review)" >> "$report_file"
    echo "" >> "$report_file"

    if [[ -s "$targets_waf" ]]; then
        while IFS= read -r line; do
            echo "- ${line}" >> "$report_file"
        done < "$targets_waf"
    fi

    if [[ -s "$targets_cdn" ]]; then
        while IFS= read -r line; do
            echo "- ${line}" >> "$report_file"
        done < "$targets_cdn"
    fi

    if [[ ! -s "$targets_waf" && ! -s "$targets_cdn" ]]; then
        echo "_Nenhum host protegido detectado._" >> "$report_file"
    fi

    echo "" >> "$report_file"

    # Interesting hosts section
    echo "---" >> "$report_file"
    echo "" >> "$report_file"
    echo "## Interesting Hosts (non-200)" >> "$report_file"
    echo "" >> "$report_file"

    if [[ -s "$targets_interesting" ]]; then
        while IFS= read -r line; do
            echo "- ${line}" >> "$report_file"
        done < "$targets_interesting"
    else
        echo "_Nenhum host com status interessante._" >> "$report_file"
    fi

    echo "" >> "$report_file"

    # Recommendations
    echo "---" >> "$report_file"
    echo "" >> "$report_file"
    echo "## Recommendations" >> "$report_file"
    echo "" >> "$report_file"
    echo "1. **Prime targets** (No WAF) - Verificar manualmente todos os findings de disclosure" >> "$report_file"
    echo "2. **403 Forbidden** - Testar bypass com \`./ffuf_master.sh bypass <url>\`" >> "$report_file"
    echo "3. **WAF targets** - Considerar scan stealth manual: \`./ffuf_master.sh <url> auto 5 10 stealth\`" >> "$report_file"
    echo "4. **CDN targets** - Procurar origin IP via DNS history (SecurityTrails, ViewDNS)" >> "$report_file"
    echo "5. **API subdomains** - Aprofundar com \`./ffuf_master.sh api <url>\`" >> "$report_file"
    echo "" >> "$report_file"

    # End phase timer
    [[ $PHASE_START_TIME -gt 0 ]] && end_phase_timer
    PHASE_START_TIME=0

    # Total execution time
    local total_elapsed=$(( $(date +%s) - SCRIPT_START_TIME ))

    # Final summary box
    echo ""
    draw_line "top"
    box_center "${BOLD}${RED}HUNT MODE${NC} ${BOLD}- RELATÓRIO FINAL${NC}"
    draw_line "mid"
    box_left "${CYAN}Domínio:${NC}              $domain"
    box_left "${CYAN}Subdomínios:${NC}          $total_subs"
    box_left "${CYAN}Hosts ativos:${NC}         $total_alive"
    draw_line "sep"
    box_left "${CYAN}200 OK:${NC}               $count_200"
    box_left "${GREEN}No WAF (prime):${NC}       ${BOLD}${GREEN}${no_waf_final}${NC}"
    box_left "${YELLOW}WAF:${NC}                  $waf_count"
    box_left "${BLUE}CDN:${NC}                  $cdn_count"
    draw_line "sep"
    box_left "${CYAN}Content findings:${NC}     ${GREEN}$total_findings${NC}"
    box_left "${CYAN}Tempo total:${NC}          ${BOLD}$(format_elapsed $total_elapsed)${NC}"
    draw_line "sep"
    box_left "${CYAN}Arquivos gerados:${NC}"
    box_left "  • targets_200ok.txt  (${count_200} hosts)"
    box_left "  • targets_no_waf.txt (${no_waf_final} prime)"
    box_left "  • targets_waf.txt    (${waf_count} protected)"
    box_left "  • scans/*.json       (ffuf results)"
    box_left "  • ${BOLD}REPORT.md${NC}          (full report)"
    draw_line "bot"
    echo ""

    if [[ $total_findings -gt 0 ]]; then
        log_success "Hunt completo! $total_findings endpoints encontrados em targets sem proteção."
    elif [[ $no_waf_final -gt 0 ]]; then
        log_warning "Hunt completo. Nenhum endpoint encontrado nos targets sem WAF."
    else
        log_warning "Hunt completo. Todos os targets estão protegidos por WAF/CDN."
    fi

    echo -e "\n${CYAN}Diretório de resultados:${NC} ${recon_dir}"
    echo -e "${CYAN}Relatório:${NC} ${recon_dir}/REPORT.md"
}

# ============================================================================
# HUNT LIST MODE - Import external domain list → Permutate → Validate → Triage → Fuzz
# ============================================================================

hunt_list() {
    local input_file="$1"
    local wordlist="$2"
    local threads="${3:-60}"
    local rate="${4:-100}"

    if [[ -z "$input_file" ]]; then
        log_error "Uso: ./ffuf_master.sh --hunt-list <arquivo_ou_url> [wordlist] [threads] [rate]"
        echo ""
        echo "Hunt List: Importa lista de domínios, gera permutações, valida, triage, fuzz"
        echo ""
        echo "Exemplos:"
        echo "  ./ffuf_master.sh --hunt-list domains.txt"
        echo "  ./ffuf_master.sh --hunt-list https://gist.githubusercontent.com/.../raw"
        echo "  ./ffuf_master.sh --hunt-list scope.txt auto 80 150"
        return 1
    fi

    # Encontrar wordlist
    wordlist=$(find_wordlist "$wordlist") || return 1

    # Criar diretório de resultados
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local recon_dir="${RESULTS_DIR}/hunt_list_${timestamp}"
    mkdir -p "${recon_dir}/scans"

    local original_file="${recon_dir}/original_domains.txt"

    # ===========================================================
    # PHASE 1: IMPORT (file or URL)
    # ===========================================================
    log_phase "PHASE 1: IMPORT DOMAIN LIST" "1" "7"

    if [[ "$input_file" =~ ^https?:// ]]; then
        log_info "Downloading domain list from URL..."
        start_spinner "Downloading..."
        curl -sL "$input_file" > "${recon_dir}/raw_input.txt" 2>/dev/null
        stop_spinner
    elif [[ -f "$input_file" ]]; then
        cp "$input_file" "${recon_dir}/raw_input.txt"
    else
        log_error "Arquivo não encontrado: $input_file"
        return 1
    fi

    # Clean: extract valid domains only
    grep -oE '[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}' "${recon_dir}/raw_input.txt" \
        | tr '[:upper:]' '[:lower:]' | sort -u > "$original_file"

    local total_imported=$(wc -l < "$original_file")
    log_success "Importados: ${GREEN}${total_imported}${NC} domínios únicos"

    if [[ $total_imported -eq 0 ]]; then
        log_error "Nenhum domínio válido encontrado no input!"
        return 1
    fi

    # Extract root domains and subdomain prefixes for analysis
    local roots_file="${recon_dir}/root_domains.txt"
    local prefixes_file="${recon_dir}/prefixes.txt"

    python3 -c "
import sys
domains = open('$original_file').read().strip().split('\n')
roots = set()
prefixes = set()
cc_tlds = {'co', 'com', 'org', 'net', 'gen', 'ac', 'gov', 'edu'}
for d in domains:
    parts = d.strip().split('.')
    if len(parts) >= 3 and parts[-2] in cc_tlds:
        root = '.'.join(parts[-3:])
        prefix = '.'.join(parts[:-3])
    elif len(parts) >= 2:
        root = '.'.join(parts[-2:])
        prefix = '.'.join(parts[:-2])
    else:
        continue
    roots.add(root)
    if prefix:
        prefixes.add(prefix.split('.')[0])  # first-level prefix only
with open('$roots_file', 'w') as f:
    f.write('\n'.join(sorted(roots)) + '\n')
with open('$prefixes_file', 'w') as f:
    f.write('\n'.join(sorted(prefixes)) + '\n')
print(f'Root domains: {len(roots)}')
print(f'Unique prefixes: {len(prefixes)}')
" 2>/dev/null

    local total_roots=$(wc -l < "$roots_file" 2>/dev/null || echo 0)
    local total_prefixes=$(wc -l < "$prefixes_file" 2>/dev/null || echo 0)

    echo ""
    draw_line "top"
    box_center "${BOLD}${RED}HUNT LIST MODE${NC} ${BOLD}- FFUF MASTER v${SCRIPT_VERSION}${NC}"
    box_center "${RED}@${GREEN}ofj${YELLOW}aaah${NC}"
    draw_line "mid"
    box_left "Source:   ${YELLOW}$(basename "$input_file")${NC}"
    box_left "Imported: ${GREEN}${total_imported}${NC} domains | ${total_roots} roots | ${total_prefixes} prefixes"
    box_left "Strategy: ${RED}Permutate${NC} → ${YELLOW}Resolve${NC} → ${GREEN}Triage${NC} → ${BOLD}Fuzz${NC}"
    box_left "Threads:  ${threads} | Rate: ${rate}/s"
    box_left "Wordlist: $(basename "$wordlist")"
    box_left "Output:   ${recon_dir}"
    draw_line "bot"
    echo ""

    # ===========================================================
    # PHASE 2: PERMUTATION GENERATION
    # ===========================================================
    log_phase "PHASE 2: PERMUTATION GENERATION" "2" "7"

    local permutations_file="${recon_dir}/permutations.txt"

    log_info "Gerando permutações baseadas nos padrões encontrados..."

    python3 << 'PERMEOF'
import os

outdir = os.environ.get("RECON_DIR", "")
if not outdir:
    outdir = "$recon_dir"

original_file = outdir + "/original_domains.txt"
roots_file = outdir + "/root_domains.txt"
prefixes_file = outdir + "/prefixes.txt"
perm_file = outdir + "/permutations.txt"

with open(original_file) as f:
    original = set(line.strip() for line in f if line.strip())

with open(roots_file) as f:
    roots = [line.strip() for line in f if line.strip()]

with open(prefixes_file) as f:
    existing_prefixes = set(line.strip() for line in f if line.strip())

# Environment suffixes to try on existing prefixes
env_suffixes = ['-d', '-q', '-s', '-staging', '-dev', '-test', '-qa',
                '-integration', '-preprod', '-old', '-new', '-uat',
                '-prod', '-beta', '-alpha', '-demo', '-sandbox', '-internal']

# High-value prefixes to try on all key roots
hv_prefixes = [
    'api', 'api-staging', 'api-qa', 'api-dev', 'api-internal', 'api-v2',
    'admin', 'admin-panel', 'backoffice', 'dashboard',
    'dev', 'devel', 'staging', 'stage', 'test', 'qa', 'uat', 'preprod', 'sandbox',
    'internal', 'intranet', 'corp', 'private',
    'auth', 'oauth', 'sso', 'login', 'idp', 'mfa',
    'cdn', 'origin', 'origin-www', 'origin-api',
    'git', 'gitlab', 'github', 'bitbucket', 'code', 'repository',
    'jenkins', 'ci', 'build', 'deploy',
    'jira', 'confluence', 'wiki', 'docs',
    'grafana', 'prometheus', 'monitoring', 'kibana', 'splunk',
    'sonarqube', 'nexus', 'artifactory',
    'docker', 'dockerregistry', 'registry', 'harbor', 'k8s',
    'db', 'mysql', 'postgres', 'redis', 'mongo',
    'mail', 'webmail', 'smtp', 'ftp', 'sftp',
    'vpn', 'sslvpn', 'remote', 'citrix', 'bastion',
    'phpmyadmin', 'adminer', 'pgadmin',
    'cms', 'directus', 'strapi', 'wp',
    'shop', 'store', 'graphql', 'gateway', 'rest',
    'app', 'apps', 'mobile', 'mobile-api',
    'beta', 'alpha', 'next', 'preview', 'canary',
    'status', 'health', 'debug', 'trace',
    'config', 'vault', 'consul', 'secrets',
    'proxy', 'nginx', 'traefik',
    'crm', 'erp', 'sap',
    'legacy', 'old', 'v1', 'v2', 'v3',
    'static', 'assets', 'media', 'cdn-origin',
    'analytics', 'billing', 'payment',
    'support', 'helpdesk', 'zendesk',
    'lab', 'labs', 'research', 'temp',
    'portal', 'partner', 'b2b',
    'account', 'accounts', 'my', 'profile',
    'data', 'airflow', 'etl',
    'defectdojo', 'security', 'pentest',
    'jupyter', 'notebook', 'rstudio',
    'looker', 'tableau', 'superset',
    'n8n', 'workflow',
]

# Select key roots (max 30 most-subdomain-heavy roots)
from collections import Counter
root_counts = Counter()
cc_tlds = {'co', 'com', 'org', 'net', 'gen', 'ac', 'gov', 'edu'}
root_prefix_map = {}
for d in original:
    parts = d.split('.')
    if len(parts) >= 3 and parts[-2] in cc_tlds:
        root = '.'.join(parts[-3:])
        prefix = '.'.join(parts[:-3])
    elif len(parts) >= 2:
        root = '.'.join(parts[-2:])
        prefix = '.'.join(parts[:-2])
    else:
        continue
    root_counts[root] += 1
    if root not in root_prefix_map:
        root_prefix_map[root] = set()
    if prefix:
        root_prefix_map[root].add(prefix.split('.')[0])

key_roots = [r for r, _ in root_counts.most_common(30)]

perms = set()

# Strategy 1: High-value prefixes on key roots
for root in key_roots:
    for prefix in hv_prefixes:
        candidate = f"{prefix}.{root}"
        if candidate not in original:
            perms.add(candidate)

# Strategy 2: Environment variants on existing prefixes of key roots
for root in key_roots[:15]:
    for prefix in list(root_prefix_map.get(root, set()))[:50]:
        for suffix in env_suffixes:
            candidate = f"{prefix}{suffix}.{root}"
            if candidate not in original:
                perms.add(candidate)

# Strategy 3: Cross-pollinate prefixes from top root to other roots
if key_roots:
    top_root = key_roots[0]
    top_prefixes = list(root_prefix_map.get(top_root, set()))[:80]
    for prefix in top_prefixes:
        for root in key_roots[1:20]:
            candidate = f"{prefix}.{root}"
            if candidate not in original:
                perms.add(candidate)

perms = perms - original

with open(perm_file, 'w') as f:
    for p in sorted(perms):
        f.write(p + '\n')

print(f"Generated {len(perms)} permutations")
PERMEOF

    # Fix: pass env var properly
    RECON_DIR="$recon_dir" python3 << PERMEOF2
import os
outdir = "$recon_dir"

original_file = outdir + "/original_domains.txt"
roots_file = outdir + "/root_domains.txt"
prefixes_file = outdir + "/prefixes.txt"
perm_file = outdir + "/permutations.txt"

with open(original_file) as f:
    original = set(line.strip() for line in f if line.strip())

with open(roots_file) as f:
    roots = [line.strip() for line in f if line.strip()]

with open(prefixes_file) as f:
    existing_prefixes = set(line.strip() for line in f if line.strip())

env_suffixes = ['-d', '-q', '-s', '-staging', '-dev', '-test', '-qa',
                '-integration', '-preprod', '-old', '-new', '-uat',
                '-prod', '-beta', '-alpha', '-demo', '-sandbox', '-internal']

hv_prefixes = [
    'api', 'api-staging', 'api-qa', 'api-dev', 'api-internal', 'api-v2',
    'admin', 'admin-panel', 'backoffice', 'dashboard',
    'dev', 'devel', 'staging', 'stage', 'test', 'qa', 'uat', 'preprod', 'sandbox',
    'internal', 'intranet', 'corp', 'private',
    'auth', 'oauth', 'sso', 'login', 'idp', 'mfa',
    'cdn', 'origin', 'origin-www', 'origin-api',
    'git', 'gitlab', 'github', 'bitbucket', 'code', 'repository',
    'jenkins', 'ci', 'build', 'deploy',
    'jira', 'confluence', 'wiki', 'docs',
    'grafana', 'prometheus', 'monitoring', 'kibana', 'splunk',
    'sonarqube', 'nexus', 'artifactory',
    'docker', 'dockerregistry', 'registry', 'harbor', 'k8s',
    'db', 'mysql', 'postgres', 'redis', 'mongo',
    'mail', 'webmail', 'smtp', 'ftp', 'sftp',
    'vpn', 'sslvpn', 'remote', 'citrix', 'bastion',
    'phpmyadmin', 'adminer', 'pgadmin',
    'cms', 'directus', 'strapi', 'wp',
    'shop', 'store', 'graphql', 'gateway', 'rest',
    'app', 'apps', 'mobile', 'mobile-api',
    'beta', 'alpha', 'next', 'preview', 'canary',
    'status', 'health', 'debug', 'trace',
    'config', 'vault', 'consul', 'secrets',
    'proxy', 'nginx', 'traefik',
    'crm', 'erp', 'sap',
    'legacy', 'old', 'v1', 'v2', 'v3',
    'static', 'assets', 'media', 'cdn-origin',
    'analytics', 'billing', 'payment',
    'support', 'helpdesk', 'zendesk',
    'lab', 'labs', 'research', 'temp',
    'portal', 'partner', 'b2b',
    'account', 'accounts', 'my', 'profile',
    'data', 'airflow', 'etl',
    'defectdojo', 'security', 'pentest',
    'jupyter', 'notebook', 'rstudio',
    'looker', 'tableau', 'superset',
    'n8n', 'workflow',
]

from collections import Counter
cc_tlds = {'co', 'com', 'org', 'net', 'gen', 'ac', 'gov', 'edu'}
root_counts = Counter()
root_prefix_map = {}
for d in original:
    parts = d.strip().split('.')
    if len(parts) >= 3 and parts[-2] in cc_tlds:
        root = '.'.join(parts[-3:])
        prefix = '.'.join(parts[:-3])
    elif len(parts) >= 2:
        root = '.'.join(parts[-2:])
        prefix = '.'.join(parts[:-2])
    else:
        continue
    root_counts[root] += 1
    if root not in root_prefix_map:
        root_prefix_map[root] = set()
    if prefix:
        root_prefix_map[root].add(prefix.split('.')[0])

key_roots = [r for r, _ in root_counts.most_common(30)]

perms = set()

for root in key_roots:
    for prefix in hv_prefixes:
        candidate = f"{prefix}.{root}"
        if candidate not in original:
            perms.add(candidate)

for root in key_roots[:15]:
    for prefix in list(root_prefix_map.get(root, set()))[:50]:
        for suffix in env_suffixes:
            candidate = f"{prefix}{suffix}.{root}"
            if candidate not in original:
                perms.add(candidate)

if key_roots:
    top_root = key_roots[0]
    top_prefixes = list(root_prefix_map.get(top_root, set()))[:80]
    for prefix in top_prefixes:
        for root in key_roots[1:20]:
            candidate = f"{prefix}.{root}"
            if candidate not in original:
                perms.add(candidate)

perms = perms - original

with open(perm_file, 'w') as f:
    for p in sorted(perms):
        f.write(p + '\n')

print(f"Generated {len(perms)} permutations")
PERMEOF2

    local perm_count=$(wc -l < "$permutations_file" 2>/dev/null || echo 0)
    log_success "Geradas ${GREEN}${perm_count}${NC} permutações"

    # ===========================================================
    # PHASE 3: DNS RESOLUTION
    # ===========================================================
    log_phase "PHASE 3: DNS RESOLUTION" "3" "7"

    local resolved_file="${recon_dir}/resolved_new.txt"
    local all_targets="${recon_dir}/all_targets.txt"

    log_info "Resolvendo ${perm_count} permutações..."

    if command -v dnsx &>/dev/null; then
        start_spinner "Resolvendo DNS com dnsx..."
        cat "$permutations_file" | dnsx -silent -retry 2 -rate-limit 500 \
            -o "$resolved_file" 2>/dev/null
        stop_spinner
    elif command -v puredns &>/dev/null; then
        start_spinner "Resolvendo DNS com puredns..."
        local resolvers=""
        [[ -f "${WORDLISTS_DIR}/resolvers.txt" ]] && resolvers="-r ${WORDLISTS_DIR}/resolvers.txt"
        puredns resolve "$permutations_file" $resolvers \
            -w "$resolved_file" 2>/dev/null
        stop_spinner
    else
        log_warning "dnsx/puredns não encontrados. Usando dig (mais lento)..."
        > "$resolved_file"
        local dig_count=0
        while IFS= read -r domain; do
            if dig +short "$domain" 2>/dev/null | grep -qE '^[0-9]+\.'; then
                echo "$domain" >> "$resolved_file"
                ((dig_count++))
            fi
        done < "$permutations_file"
    fi

    local resolved_count=$(wc -l < "$resolved_file" 2>/dev/null || echo 0)
    log_success "Resolvidos: ${GREEN}${resolved_count}${NC} novos domínios"

    # Combine: original + newly resolved
    cat "$original_file" "$resolved_file" 2>/dev/null | sort -u > "$all_targets"
    local total_targets=$(wc -l < "$all_targets")
    log_info "Total targets para probing: ${total_targets}"

    # ===========================================================
    # PHASE 4: HTTPX PROBING
    # ===========================================================
    log_phase "PHASE 4: PROBING HOSTS (httpx extended)" "4" "7"

    local alive_file="${recon_dir}/alive.txt"
    local alive_details="${recon_dir}/alive_details.txt"

    log_info "Verificando hosts ativos (${total_targets} targets)..."

    if command -v httpx &>/dev/null; then
        start_spinner "Executando httpx com detecção de tecnologia..."
        httpx -l "$all_targets" -silent -timeout 10 -retries 1 \
            -status-code -content-length -title -tech-detect -no-fallback \
            -threads 100 \
            > "$alive_details" 2>/dev/null
        stop_spinner

        awk '{print $1}' "$alive_details" | sort -u > "$alive_file"
    else
        log_error "httpx não encontrado!"
        return 1
    fi

    local total_alive=$(wc -l < "$alive_file" 2>/dev/null || echo "0")
    log_success "$total_alive hosts ativos"

    if [[ "$total_alive" -eq 0 ]]; then
        log_error "Nenhum host ativo encontrado!"
        return 1
    fi

    # ===========================================================
    # PHASE 5: TRIAGE (200 OK + WAF/CDN + catch-all detection)
    # ===========================================================
    log_phase "PHASE 5: TRIAGE (200 OK + WAF/CDN + catch-all)" "5" "7"

    local targets_200ok="${recon_dir}/targets_200ok.txt"
    local targets_interesting="${recon_dir}/targets_interesting.txt"
    local targets_no_waf="${recon_dir}/targets_no_waf.txt"
    local targets_waf="${recon_dir}/targets_waf.txt"
    local targets_real="${recon_dir}/targets_real.txt"

    > "$targets_200ok"
    > "$targets_interesting"
    > "$targets_no_waf"
    > "$targets_waf"
    > "$targets_real"

    # Parse httpx output (strip ANSI codes)
    while IFS= read -r line; do
        local clean_line url status
        clean_line=$(echo "$line" | sed 's/\x1b\[[0-9;]*m//g')
        url=$(echo "$clean_line" | awk '{print $1}')
        status=$(echo "$clean_line" | grep -oP '\[\K[0-9]+(?=\])' | head -1)

        [[ -z "$url" || -z "$status" ]] && continue

        case "$status" in
            200)
                echo "$url" >> "$targets_200ok"
                ;;
            301|302|307|308|401|403)
                echo "${url} [${status}]" >> "$targets_interesting"
                ;;
        esac
    done < "$alive_details"

    local count_200=$(wc -l < "$targets_200ok" 2>/dev/null || echo 0)
    local count_interesting=$(wc -l < "$targets_interesting" 2>/dev/null || echo 0)

    log_success "${count_200} hosts com 200 OK"
    [[ $count_interesting -gt 0 ]] && log_info "${count_interesting} hosts com status interessante"

    if [[ $count_200 -eq 0 ]]; then
        log_warning "Nenhum host com 200 OK encontrado!"
    fi

    # WAF/CDN detection via cdncheck + catch-all filtering on 200 OK hosts
    local waf_count=0
    local no_waf_count=0
    local catchall_count=0

    if [[ $count_200 -gt 0 ]]; then
        echo ""
        log_info "Detectando WAF/CDN nos hosts 200 OK..."

        # Fase 1: Bulk CDN/WAF check
        local cdn_tmp="${recon_dir}/cdn_detected.txt"
        local waf_tmp="${recon_dir}/waf_detected.txt"
        local clean_tmp="${recon_dir}/clean_after_cdn.txt"
        bulk_cdn_check "$targets_200ok" "$clean_tmp" "$cdn_tmp" "$waf_tmp"

        # Mover WAF/CDN para targets_waf (ambos são excluídos do scan)
        cat "$waf_tmp" >> "$targets_waf" 2>/dev/null
        cat "$cdn_tmp" >> "$targets_waf" 2>/dev/null

        # Fase 2: Catch-all detection nos hosts limpos
        echo ""
        log_info "Detectando catch-all nos hosts limpos..."
        local clean_count
        clean_count=$(wc -l < "$clean_tmp" 2>/dev/null || echo 0)
        local current=0

        while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            ((current++))
            show_progress "$current" "$clean_count" "Catch-all detection"

            # Catch-all detection: probe random path, compare size
            local random_path
            random_path=$(head /dev/urandom | tr -dc 'a-z0-9' | head -c 20)
            local probe_resp
            probe_resp=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" \
                "${url%/}/${random_path}" --max-time 5 2>/dev/null)
            local probe_code probe_size
            probe_code=$(echo "$probe_resp" | cut -d'|' -f1)
            probe_size=$(echo "$probe_resp" | cut -d'|' -f2)

            # Second probe with different length
            local random_path2
            random_path2=$(head /dev/urandom | tr -dc 'a-z0-9' | head -c 32)
            local probe_resp2
            probe_resp2=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" \
                "${url%/}/${random_path2}" --max-time 5 2>/dev/null)
            local probe_size2
            probe_size2=$(echo "$probe_resp2" | cut -d'|' -f2)

            if [[ "$probe_code" == "200" && "$probe_size" == "$probe_size2" && "$probe_size" != "0" ]]; then
                ((catchall_count++))
                continue
            fi

            # Real target: no WAF, no CDN, no catch-all
            echo "$url" >> "$targets_no_waf"
            echo "$url" >> "$targets_real"
            ((no_waf_count++))

        done < "$clean_tmp"

        waf_count=$(wc -l < "$targets_waf" 2>/dev/null || echo 0)
        rm -f "$cdn_tmp" "$waf_tmp" "$clean_tmp"
    fi

    echo ""
    echo ""

    # Triage summary box
    draw_line "top"
    box_center "${BOLD}TRIAGE SUMMARY${NC}"
    draw_line "mid"
    box_left "${GREEN}200 OK Total:${NC}         ${count_200} hosts"
    draw_line "sep"
    box_left "${GREEN}✓ Real (No WAF/CDN):${NC}  ${BOLD}${GREEN}${no_waf_count}${NC} (prime targets)"
    box_left "${YELLOW}⚠ WAF/CDN Protected:${NC} ${waf_count} hosts"
    box_left "${ORANGE}↻ Catch-all (soft-404):${NC} ${catchall_count} hosts"
    draw_line "sep"
    box_left "${CYAN}Interesting (non-200):${NC} ${count_interesting} hosts"
    box_left "${CYAN}New from permutation:${NC} ${resolved_count} domains"
    draw_line "bot"
    echo ""

    if [[ -s "$targets_real" ]]; then
        log_success "Prime targets:"
        while read -r url; do
            local domain
            domain=$(echo "$url" | sed -E 's#^https?://##; s#[/:].*##')
            local ctx="DIR"
            if echo "$domain" | grep -qiE '^(api[0-9]*|api-|actions-service|gateway|graphql|rest|oauth)'; then
                ctx="API"
            elif echo "$domain" | grep -qiE '^(admin|backoffice|dashboard|accreditation|account)'; then
                ctx="APP"
            fi
            echo -e "  ${GREEN}🎯${NC} [${ctx}] ${BOLD}${url}${NC}"
        done < "$targets_real"
        echo ""
    fi

    # ===========================================================
    # PHASE 6: DEEP SCAN (no-WAF targets)
    # ===========================================================
    log_phase "PHASE 6: DEEP SCAN (disclosure + ffuf)" "6" "7"

    if [[ ! -s "$targets_real" ]]; then
        log_warning "Nenhum target real para deep scan."
        log_info "Todos os 200 OK são catch-all ou protegidos por WAF/CDN."
    else
        local scan_dir="${recon_dir}/scans"
        local target_count
        target_count=$(wc -l < "$targets_real")

        # --- 6a: Disclosure check ---
        echo ""
        log_info "${BOLD}[6a] Disclosure Check${NC}"
        echo ""

        while IFS= read -r url; do
            echo -e "  ${CYAN}Disclosure:${NC} ${YELLOW}${url}${NC}"
            check_disclosure "$url" 2>/dev/null
            echo ""
        done < "$targets_real"

        # --- 6b: Aggressive ffuf ---
        echo ""
        log_info "${BOLD}[6b] Aggressive Content Discovery (ffuf)${NC}"
        echo ""

        create_api_wordlist 2>/dev/null
        local api_wordlist="${WORDLISTS_DIR}/api-master.txt"
        [[ ! -f "$api_wordlist" ]] && api_wordlist="$wordlist"

        local progress_file="${scan_dir}/.progress"
        echo "0" > "$progress_file"

        process_host() {
            local url="$1"
            local scan_dir="$2"
            local default_wordlist="$3"
            local job_threads="$4"
            local job_rate="$5"
            local timeout_val="$6"
            local maxtime="$7"
            local recursion_depth="$8"
            local total="$9"
            local progress_file="${10}"
            local api_wordlist="${11}"
            local wordlists_dir="${12}"

            local clean_name=$(echo "$url" | sed -E 's#^https?://##; s#[/:.]#_#g')
            local output_file="${scan_dir}/${clean_name}.json"
            local log_file="${scan_dir}/${clean_name}.log"

            local current
            if command -v flock &>/dev/null; then
                current=$(flock -x "$progress_file" bash -c 'c=$(<"$1"); echo $((c + 1)) > "$1"; echo $((c + 1))' _ "$progress_file")
            else
                current=$(cat "$progress_file" 2>/dev/null || echo 0)
                echo $((current + 1)) > "$progress_file"
                current=$((current + 1))
            fi

            # Detect API vs DIR context
            local subdomain=$(echo "$url" | sed -E 's#^https?://##; s#/.*##; s#:[0-9]+##')
            local is_api=false
            local wordlist="$default_wordlist"
            local context_msg=""

            if echo "$subdomain" | grep -qiE '^(api[0-9]*|api-|apis|gateway|gw|graphql|rest|v[0-9]+|actions-service)[-.]'; then
                is_api=true
            elif echo "$subdomain" | grep -qiE '(dev|stg|staging|prod|uat|qa|test)[-.]?api'; then
                is_api=true
            fi

            if $is_api && [[ -f "$api_wordlist" ]]; then
                wordlist="$api_wordlist"
                context_msg=" [API]"
            fi

            local wl_name=$(basename "$wordlist")
            echo -e "\033[0;36m[${current}/${total}]\033[0m \033[1;33m${url}\033[0m${context_msg} → ${wl_name}"

            # Calibrate
            local calibration_flags
            calibration_flags=$(calibrate_target "$url" 3)
            if [[ -n "$calibration_flags" ]]; then
                echo -e "  \033[0;33m⚠ Catch-all detectado → filtro: ${calibration_flags}\033[0m"
            fi

            if timeout $((maxtime + 30)) ffuf -c \
                -u "${url}/FUZZ" \
                -w "$wordlist" \
                -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
                -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
                -t "$job_threads" \
                -rate "$job_rate" \
                -timeout "$timeout_val" \
                -recursion \
                -recursion-depth "$recursion_depth" \
                -mc 200,201,204,301,302,307,308,401,403,405,500 \
                -fc 404 \
                -ac \
                $calibration_flags \
                -maxtime "$maxtime" \
                -maxtime-job 120 \
                -se -sf \
                -o "$output_file" \
                -of json \
                > "$log_file" 2>&1; then

                local results=$(python3 -c "import json; print(len(json.load(open('$output_file')).get('results', [])))" 2>/dev/null || echo "0")
                if [[ "$results" -gt 0 ]]; then
                    echo -e "  \033[0;32m✓ $results resultados - ${url}\033[0m"
                fi
            else
                echo -e "  \033[0;31m✗ Timeout/Erro - ${url}\033[0m"
            fi
        }
        export -f calibrate_target
        export -f process_host

        # Parallelism
        local cpu_cores=$(nproc 2>/dev/null || echo 4)
        local mem_gb=$(free -g 2>/dev/null | awk '/^Mem:/{print $7}' || echo 4)
        local max_parallel=$((cpu_cores / 2))
        [[ $max_parallel -lt 2 ]] && max_parallel=2
        [[ $max_parallel -gt 6 ]] && max_parallel=6
        [[ $max_parallel -gt $target_count ]] && max_parallel=$target_count
        [[ $mem_gb -lt $max_parallel ]] && max_parallel=$mem_gb
        [[ $max_parallel -lt 1 ]] && max_parallel=1

        local job_threads=$((threads / max_parallel))
        local job_rate=$((rate / max_parallel))
        [[ $job_threads -lt 5 ]] && job_threads=5
        [[ $job_rate -lt 10 ]] && job_rate=10

        log_info "ffuf: ${target_count} targets | ${max_parallel} parallel | ${job_threads}t/${job_rate}r per job"
        echo ""

        if command -v parallel &>/dev/null; then
            cat "$targets_real" | parallel -j "$max_parallel" --line-buffer \
                process_host {} "$scan_dir" "$wordlist" "$job_threads" "$job_rate" \
                "$DEFAULT_TIMEOUT" "$DEFAULT_MAXTIME" "$DEFAULT_RECURSION_DEPTH" \
                "$target_count" "$progress_file" "$api_wordlist" "$WORDLISTS_DIR"
        else
            cat "$targets_real" | xargs -P "$max_parallel" -I {} bash -c \
                'process_host "$@"' _ {} "$scan_dir" "$wordlist" "$job_threads" "$job_rate" \
                "$DEFAULT_TIMEOUT" "$DEFAULT_MAXTIME" "$DEFAULT_RECURSION_DEPTH" \
                "$target_count" "$progress_file" "$api_wordlist" "$WORDLISTS_DIR"
        fi

        # Filter false positives
        log_info "Filtrando falsos positivos..."
        for json_file in "${scan_dir}"/*.json; do
            [[ -f "$json_file" ]] || continue
            local raw_count=$(python3 -c "import json; print(len(json.load(open('$json_file')).get('results', [])))" 2>/dev/null || echo "0")
            if [[ "$raw_count" -gt 0 ]]; then
                filter_results "$json_file" >/dev/null 2>&1
                local filtered_file="${json_file%.json}_filtered.json"
                if [[ -f "$filtered_file" ]]; then
                    cp "$filtered_file" "$json_file"
                    rm -f "$filtered_file"
                fi
            fi
        done

        # API enum on API-context subdomains
        echo ""
        log_info "${BOLD}[6c] API Enumeration${NC}"
        local api_scanned=0
        while IFS= read -r url; do
            local subdomain=$(echo "$url" | sed -E 's#^https?://##; s#/.*##; s#:[0-9]+##')
            if echo "$subdomain" | grep -qiE '^(api[0-9]*|api-|apis|gateway|gw|graphql|rest|v[0-9]+|actions-service)[-.]'; then
                log_info "API scan: ${YELLOW}${url}${NC}"
                enum_api "$url" 2>/dev/null
                ((api_scanned++))
            fi
        done < "$targets_real"
        [[ $api_scanned -eq 0 ]] && log_info "Nenhum subdomínio API encontrado."
    fi

    # ===========================================================
    # PHASE 7: CONSOLIDATION + REPORT
    # ===========================================================
    log_phase "PHASE 7: CONSOLIDATION + REPORT" "7" "7"

    local report_file="${recon_dir}/REPORT.md"
    local scan_dir="${recon_dir}/scans"
    local total_findings=0
    local success=0

    for json_file in "${scan_dir}"/*.json; do
        [[ -f "$json_file" ]] || continue
        local count=$(python3 -c "import json; print(len(json.load(open('$json_file')).get('results', [])))" 2>/dev/null || echo "0")
        [[ "$count" -gt 0 ]] && { ((total_findings += count)); ((success++)); }
    done

    cat > "$report_file" << REPORT_EOF
# Hunt List Report

**Data:** $(date)
**Modo:** Hunt List (Import → Permutate → Resolve → Triage → Deep Scan)
**Versão:** FFUF Master v${SCRIPT_VERSION}
**Source:** $(basename "$input_file")

---

## Summary

| Metric | Value |
|--------|-------|
| Imported domains | ${total_imported} |
| Root domains | ${total_roots} |
| Permutations generated | ${perm_count} |
| New domains resolved | ${resolved_count} |
| Hosts alive | ${total_alive} |
| 200 OK | ${count_200} |
| **Real targets (no WAF)** | **${no_waf_count}** |
| WAF/CDN protected | ${waf_count} |
| Catch-all (soft-404) | ${catchall_count} |
| Content findings | ${total_findings} |

---

## Prime Targets (No WAF/CDN, Real 200 OK)

REPORT_EOF

    if [[ -s "$targets_real" ]]; then
        while read -r url; do
            echo "- ${url}" >> "$report_file"
        done < "$targets_real"
    else
        echo "_None found._" >> "$report_file"
    fi

    echo "" >> "$report_file"
    echo "---" >> "$report_file"
    echo "" >> "$report_file"
    echo "## Content Discovery Findings" >> "$report_file"
    echo "" >> "$report_file"

    for json_file in "${scan_dir}"/*.json; do
        [[ -f "$json_file" ]] || continue
        local host=$(basename "$json_file" .json | sed 's/_/./g' | sed 's/^https\.\.//; s/^http\.\.//')
        local count=$(python3 -c "import json; print(len(json.load(open('$json_file')).get('results', [])))" 2>/dev/null || echo "0")
        if [[ "$count" -gt 0 ]]; then
            echo "### ${host} (${count} findings)" >> "$report_file"
            echo "" >> "$report_file"
            python3 -c "
import json
data = json.load(open('$json_file'))
for r in data.get('results', [])[:30]:
    url = r.get('url', '')
    status = r.get('status', 0)
    length = r.get('length', 0)
    print(f'- [{status}] {url} ({length} bytes)')
" 2>/dev/null >> "$report_file"
            echo "" >> "$report_file"
        fi
    done

    # Disclosure findings
    echo "---" >> "$report_file"
    echo "" >> "$report_file"
    echo "## Disclosure Findings" >> "$report_file"
    echo "" >> "$report_file"

    local disc_found=false
    for disc_file in "${RESULTS_DIR}"/disclosure_*.txt; do
        [[ -f "$disc_file" ]] || continue
        local disc_time
        disc_time=$(stat -c %Y "$disc_file" 2>/dev/null || echo 0)
        if [[ $disc_time -ge $SCRIPT_START_TIME ]]; then
            disc_found=true
            echo "### $(basename "$disc_file")" >> "$report_file"
            echo '```' >> "$report_file"
            head -50 "$disc_file" >> "$report_file"
            echo '```' >> "$report_file"
            echo "" >> "$report_file"
        fi
    done
    $disc_found || echo "_No disclosure findings._" >> "$report_file"

    # WAF targets
    echo "" >> "$report_file"
    echo "---" >> "$report_file"
    echo "" >> "$report_file"
    echo "## WAF/CDN Protected (manual review)" >> "$report_file"
    echo "" >> "$report_file"

    if [[ -s "$targets_waf" ]]; then
        while IFS= read -r line; do
            echo "- ${line}" >> "$report_file"
        done < "$targets_waf"
    else
        echo "_None._" >> "$report_file"
    fi

    # Recommendations
    echo "" >> "$report_file"
    echo "---" >> "$report_file"
    echo "" >> "$report_file"
    echo "## Recommendations" >> "$report_file"
    echo "" >> "$report_file"
    echo "1. **Prime targets** - Manually verify all disclosure findings" >> "$report_file"
    echo "2. **403 responses** - Test bypass: \`./ffuf_master.sh bypass <url>\`" >> "$report_file"
    echo "3. **WAF targets** - Stealth scan: \`./ffuf_master.sh <url> auto 5 10 stealth\`" >> "$report_file"
    echo "4. **API subdomains** - Deep enum: \`./ffuf_master.sh api <url>\`" >> "$report_file"
    echo "5. **New resolved (${resolved_count})** - Review \`resolved_new.txt\` for manual testing" >> "$report_file"

    # End phase timer
    [[ $PHASE_START_TIME -gt 0 ]] && end_phase_timer
    PHASE_START_TIME=0

    local total_elapsed=$(( $(date +%s) - SCRIPT_START_TIME ))

    # Final summary
    echo ""
    draw_line "top"
    box_center "${BOLD}${RED}HUNT LIST${NC} ${BOLD}- RELATÓRIO FINAL${NC}"
    draw_line "mid"
    box_left "${CYAN}Source:${NC}               $(basename "$input_file")"
    box_left "${CYAN}Imported:${NC}             ${total_imported} domains"
    box_left "${CYAN}Permutations:${NC}         ${perm_count} generated"
    box_left "${CYAN}New resolved:${NC}         ${GREEN}${resolved_count}${NC}"
    box_left "${CYAN}Hosts alive:${NC}          ${total_alive}"
    draw_line "sep"
    box_left "${CYAN}200 OK:${NC}               ${count_200}"
    box_left "${GREEN}Real (no WAF):${NC}        ${BOLD}${GREEN}${no_waf_count}${NC}"
    box_left "${YELLOW}WAF/CDN:${NC}              ${waf_count}"
    box_left "${ORANGE}Catch-all:${NC}            ${catchall_count}"
    draw_line "sep"
    box_left "${CYAN}Content findings:${NC}     ${GREEN}${total_findings}${NC}"
    box_left "${CYAN}Tempo total:${NC}          ${BOLD}$(format_elapsed $total_elapsed)${NC}"
    draw_line "sep"
    box_left "${CYAN}Arquivos gerados:${NC}"
    box_left "  • resolved_new.txt   (${resolved_count} new domains)"
    box_left "  • targets_real.txt   (${no_waf_count} prime)"
    box_left "  • targets_waf.txt    (${waf_count} protected)"
    box_left "  • scans/*.json       (ffuf results)"
    box_left "  • ${BOLD}REPORT.md${NC}          (full report)"
    draw_line "bot"
    echo ""

    if [[ $total_findings -gt 0 ]]; then
        log_success "Hunt List completo! $total_findings endpoints em targets sem proteção."
    elif [[ $no_waf_count -gt 0 ]]; then
        log_warning "Hunt List completo. Nenhum endpoint nos targets sem WAF."
    else
        log_warning "Hunt List completo. Todos os targets protegidos por WAF/CDN ou catch-all."
    fi

    echo -e "\n${CYAN}Diretório:${NC} ${recon_dir}"
    echo -e "${CYAN}Relatório:${NC} ${recon_dir}/REPORT.md"
}

# ============================================================================
# DOWNLOAD DE WORDLISTS
# ============================================================================

download_wordlists() {
    log_phase "DOWNLOAD DE WORDLISTS"

    # Wordlists de diretórios
    declare -A DIR_WORDLISTS=(
        ["raft-small"]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-words.txt"
        ["raft-medium"]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-words.txt"
        ["raft-large"]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-words.txt"
        ["common"]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
        ["quickhits"]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/quickhits.txt"
        ["spring-boot"]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/spring-boot.txt"
        ["backup-files"]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Common-DB-Backups.txt"
        ["sensitive"]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/LinuxFileList.txt"
    )

    # Wordlists de API
    declare -A API_WORDLISTS=(
        ["api-endpoints"]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt"
        ["api-endpoints-res"]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints-res.txt"
        ["graphql"]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/graphql.txt"
        ["api-seen-in-wild"]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-seen-in-wild.txt"
        ["swagger-wordlist"]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/swagger.txt"
    )

    # Wordlists de DNS
    declare -A DNS_WORDLISTS=(
        ["dns-top1million"]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt"
        ["dns-bitquark"]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/bitquark-subdomains-top100000.txt"
        ["dns-jhaddix"]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/dns-Jhaddix.txt"
    )

    log_info "Baixando wordlists de DIRETÓRIOS..."
    for name in "${!DIR_WORDLISTS[@]}"; do
        local output="${WORDLISTS_DIR}/${name}.txt"
        if [[ -f "$output" ]]; then
            log_success "$name já existe ($(wc -l < "$output") linhas)"
        else
            log_info "Baixando $name..."
            if curl -sL "${DIR_WORDLISTS[$name]}" -o "$output" 2>/dev/null; then
                log_success "$name baixado ($(wc -l < "$output") linhas)"
            else
                log_error "Falha ao baixar $name"
            fi
        fi
    done

    echo ""
    log_info "Baixando wordlists de API..."
    for name in "${!API_WORDLISTS[@]}"; do
        local output="${WORDLISTS_DIR}/${name}.txt"
        if [[ -f "$output" ]]; then
            log_success "$name já existe ($(wc -l < "$output") linhas)"
        else
            log_info "Baixando $name..."
            if curl -sL "${API_WORDLISTS[$name]}" -o "$output" 2>/dev/null; then
                log_success "$name baixado ($(wc -l < "$output") linhas)"
            else
                log_error "Falha ao baixar $name"
            fi
        fi
    done

    echo ""
    log_info "Baixando wordlists de DNS..."
    for name in "${!DNS_WORDLISTS[@]}"; do
        local output="${WORDLISTS_DIR}/${name}.txt"
        if [[ -f "$output" ]]; then
            log_success "$name já existe ($(wc -l < "$output") linhas)"
        else
            log_info "Baixando $name..."
            if curl -sL "${DNS_WORDLISTS[$name]}" -o "$output" 2>/dev/null; then
                log_success "$name baixado ($(wc -l < "$output") linhas)"
            else
                log_error "Falha ao baixar $name"
            fi
        fi
    done

    # Criar wordlist combinada de diretórios
    echo ""
    log_info "Criando master wordlist de diretórios..."
    cat "${WORDLISTS_DIR}/quickhits.txt" "${WORDLISTS_DIR}/common.txt" "${WORDLISTS_DIR}/raft-small.txt" 2>/dev/null | sort -u > "${WORDLISTS_DIR}/master.txt"
    log_success "Master DIR wordlist: $(wc -l < "${WORDLISTS_DIR}/master.txt") linhas"

    # Criar wordlist combinada de API
    log_info "Criando master wordlist de API..."
    cat "${WORDLISTS_DIR}/api-endpoints.txt" "${WORDLISTS_DIR}/api-endpoints-res.txt" \
        "${WORDLISTS_DIR}/api-seen-in-wild.txt" "${WORDLISTS_DIR}/graphql.txt" 2>/dev/null | sort -u > "${WORDLISTS_DIR}/api-master.txt"
    log_success "Master API wordlist: $(wc -l < "${WORDLISTS_DIR}/api-master.txt") linhas"

    # Criar wordlist combinada de DNS
    log_info "Criando master wordlist de DNS..."
    cat "${WORDLISTS_DIR}/dns-top1million.txt" 2>/dev/null | head -50000 | sort -u > "${WORDLISTS_DIR}/dns-wordlist.txt"
    log_success "Master DNS wordlist: $(wc -l < "${WORDLISTS_DIR}/dns-wordlist.txt") linhas"

    echo ""
    log_success "Download completo!"
    log_info "Diretório: ${WORDLISTS_DIR}"
}

# ============================================================================
# FUNÇÃO PRINCIPAL: FULL RECON (subfinder → httpx → ffuf)
# ============================================================================

full_recon() {
    local domain="$1"
    local wordlist="$2"
    local threads="${3:-$DEFAULT_THREADS}"
    local rate="${4:-$DEFAULT_RATE}"
    local mode="${5:-normal}"  # normal, stealth, aggressive

    if [[ -z "$domain" ]]; then
        log_error "Uso: ./ffuf_master.sh <dominio> [wordlist] [threads] [rate] [mode]"
        echo ""
        echo "Exemplos:"
        echo "  ./ffuf_master.sh target.com"
        echo "  ./ffuf_master.sh target.com /path/to/wordlist.txt"
        echo "  ./ffuf_master.sh target.com auto 40 100"
        echo "  ./ffuf_master.sh target.com auto 10 10 stealth"
        echo ""
        echo "Modos:"
        echo "  normal     - 30 threads, 50 req/s (padrão)"
        echo "  stealth    - 5 threads, 10 req/s (para WAF)"
        echo "  aggressive - 50 threads, 150 req/s (sem WAF)"
        return 1
    fi

    # Remover protocolo se incluído
    domain=$(echo "$domain" | sed -E 's#^https?://##; s#/$##')

    # Encontrar wordlist
    wordlist=$(find_wordlist "$wordlist") || return 1

    # Ajustar configurações por modo
    case "$mode" in
        stealth)
            threads=5
            rate=10
            log_warning "Modo STEALTH ativado (lento, para WAF)"
            ;;
        aggressive)
            threads=50
            rate=150
            log_warning "Modo AGGRESSIVE ativado (rápido, pode causar bloqueio)"
            ;;
    esac

    # Criar diretório de resultados
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local recon_dir="${RESULTS_DIR}/${domain}_recon_${timestamp}"
    mkdir -p "${recon_dir}/scans"

    echo ""
    draw_line "top"
    box_center "FFUF MASTER - BUG BOUNTY RECON v${SCRIPT_VERSION}"
    box_center "${RED}@${GREEN}ofj${YELLOW}aaah${NC}"
    draw_line "mid"
    box_left "Target:   ${YELLOW}${domain}${NC}"
    box_left "Mode:     ${GREEN}${mode}${NC} | Threads: ${threads} | Rate: ${rate}/s"
    box_left "Wordlist: $(basename "$wordlist") ($(wc -l < "$wordlist") palavras)"
    box_left "Output:   ${recon_dir}"
    draw_line "bot"
    echo ""

    # ========================================
    # FASE 1: DESCOBERTA PASSIVA DE SUBDOMÍNIOS
    # ========================================
    log_phase "FASE 1: DESCOBERTA DE SUBDOMÍNIOS + VARIAÇÕES DE TLD" "1" "5"

    local subdomains_file="${recon_dir}/subdomains.txt"
    local subfinder_file="${recon_dir}/subfinder.txt"
    local tldfinder_file="${recon_dir}/tldfinder.txt"
    local subfinder_count=0
    local tldfinder_count=0

    # Executar subfinder
    log_info "Executando subfinder em ${domain}..."
    if command -v subfinder &>/dev/null; then
        subfinder -d "$domain" -all -recursive -silent 2>/dev/null | sort -u > "$subfinder_file"
        subfinder_count=$(wc -l < "$subfinder_file" 2>/dev/null || echo 0)
        log_success "subfinder: ${GREEN}${subfinder_count}${NC} subdomínios"
    else
        log_warning "subfinder não encontrado!"
        log_info "Instale: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        touch "$subfinder_file"
    fi

    # Descobrir variações de TLD
    local tld_raw="${recon_dir}/tld_variations_raw.txt"
    local tld_valid="${recon_dir}/tld_variations_valid.txt"
    local tld_invalid="${recon_dir}/tld_variations_invalid.txt"
    local tld_validated=0

    echo ""
    log_info "Buscando variações de TLD do domínio..."

    # Primeiro tentar tldfinder (para TLDs privados como .google, .amazon)
    if command -v tldfinder &>/dev/null; then
        tldfinder -d "$domain" -silent 2>/dev/null | sort -u > "${recon_dir}/tldfinder_private.txt"
        local private_count=$(wc -l < "${recon_dir}/tldfinder_private.txt" 2>/dev/null || echo 0)
        if [[ $private_count -gt 0 ]]; then
            log_success "tldfinder: ${GREEN}${private_count}${NC} TLDs privados"
            cat "${recon_dir}/tldfinder_private.txt" >> "$tld_raw"
        fi
    fi

    # Descobrir variações de TLD comuns (.com, .net, .org, etc.)
    discover_tld_variations "$domain" "${recon_dir}/tld_common.txt"
    cat "${recon_dir}/tld_common.txt" >> "$tld_raw" 2>/dev/null
    sort -u "$tld_raw" -o "$tld_raw" 2>/dev/null

    tldfinder_count=$(wc -l < "$tld_raw" 2>/dev/null || echo 0)

    # Validar propriedade dos TLDs encontrados
    if [[ $tldfinder_count -gt 0 ]]; then
        echo ""
        log_info "Validando propriedade das variações de TLD..."
        filter_valid_tlds "$tld_raw" "$domain" "$tld_valid" "$tld_invalid"
        tld_validated=$(wc -l < "$tld_valid" 2>/dev/null || echo 0)

        # Usar apenas os validados (extrair só o domínio, sem score)
        cut -d'|' -f1 "$tld_valid" > "$tldfinder_file" 2>/dev/null

        # Mostrar TLDs validados com detalhes
        if [[ $tld_validated -gt 0 ]]; then
            echo ""
            local brand_name_display=$(echo "$domain" | cut -d. -f1 | tr '[:lower:]' '[:upper:]')
            echo -e "  ${GREEN}TLDs validados (pertencem à ${brand_name_display}):${NC}"
            cat "$tld_valid" | while IFS='|' read -r tld_dom score reasons; do
                echo -e "    ${GREEN}✓${NC} $tld_dom (${score}, ${reasons})"
            done
        fi
    else
        touch "$tldfinder_file"
        touch "$tld_raw"
    fi

    local tldfinder_validated=$tld_validated

    # Combinar resultados únicos (subfinder + tldfinder validados)
    cat "$subfinder_file" "$tldfinder_file" 2>/dev/null | sort -u > "$subdomains_file"

    # Adicionar domínio principal
    echo "$domain" >> "$subdomains_file"
    sort -u "$subdomains_file" -o "$subdomains_file"

    local total_subs=$(wc -l < "$subdomains_file")

    # Calcular únicos do tldfinder validado (não encontrados pelo subfinder)
    local tldfinder_unique=0
    if [[ -s "$tldfinder_file" && -s "$subfinder_file" ]]; then
        tldfinder_unique=$(grep -vxFf "$subfinder_file" "$tldfinder_file" 2>/dev/null | wc -l || echo 0)
    elif [[ -s "$tldfinder_file" ]]; then
        tldfinder_unique=$tldfinder_validated
    fi

    # Contar rejeitados
    local tld_rejected=0
    [[ -s "$tld_invalid" ]] && tld_rejected=$(wc -l < "$tld_invalid" 2>/dev/null || echo 0)

    echo ""
    draw_line "top"
    box_center "Resumo da Descoberta"
    draw_line "sep"
    box_left "subfinder:                ${GREEN}${subfinder_count}${NC} subdomínios"
    draw_line "sep"
    box_left "TLDs encontrados (DNS):   ${BLUE}${tldfinder_count}${NC} variações"
    box_left "TLDs validados (WHOIS):   ${GREEN}${tldfinder_validated}${NC} (mesma organização)"
    box_left "TLDs rejeitados:          ${RED}${tld_rejected}${NC} (outras empresas)"
    draw_line "sep"
    box_left "${BOLD}TOTAL A ESCANEAR:         ${GREEN}${total_subs}${NC}"
    draw_line "bot"

    # Mostrar amostra
    echo ""
    log_info "Amostra dos domínios a escanear:"
    head -10 "$subdomains_file" | while read -r sub; do
        echo -e "  ${BLUE}•${NC} $sub"
    done
    [[ $total_subs -gt 10 ]] && echo -e "  ${YELLOW}... e mais $((total_subs - 10)) domínios${NC}"

    # ========================================
    # FASE 1.5: PERMUTAÇÃO E BRUTEFORCE DNS
    # ========================================
    log_phase "FASE 1.5: DESCOBERTA ATIVA (permutação + bruteforce)" "2" "5"

    local permutations_file="${recon_dir}/permutations.txt"
    local bruteforce_file="${recon_dir}/bruteforce.txt"
    local all_subs_file="${recon_dir}/all_subdomains.txt"

    # Copiar subdomínios originais
    cp "$subdomains_file" "$all_subs_file"

    # Gerar permutações baseadas nos subdomínios encontrados
    log_info "Gerando permutações dos subdomínios..."
    permute_subdomains "$subdomains_file" "$domain" "$permutations_file"

    if [[ -s "$permutations_file" ]]; then
        local perm_count=$(wc -l < "$permutations_file")
        log_info "Resolvendo $perm_count permutações..."

        # Resolver permutações
        resolve_permutations "$permutations_file" "$all_subs_file"
    fi

    # Bruteforce DNS com puredns
    log_info "Iniciando bruteforce DNS..."
    bruteforce_dns "$domain" "$all_subs_file"

    # Atualizar arquivo de subdomínios
    sort -u "$all_subs_file" -o "$subdomains_file"
    local new_total=$(wc -l < "$subdomains_file")
    local discovered=$((new_total - total_subs))

    if [[ $discovered -gt 0 ]]; then
        log_success "Descobertos $discovered novos subdomínios via permutação/bruteforce!"
        log_success "Total: $new_total subdomínios"
    else
        log_info "Nenhum novo subdomínio encontrado via descoberta ativa"
    fi

    total_subs=$new_total

    # ========================================
    # FASE 2: HTTPX - Verificar Subdomínios Ativos
    # ========================================
    log_phase "FASE 2: VERIFICAÇÃO DE HOSTS ATIVOS (httpx)" "3" "5"

    local alive_file="${recon_dir}/alive.txt"
    local alive_details="${recon_dir}/alive_details.txt"

    log_info "Verificando quais subdomínios estão ativos..."

    if command -v httpx &>/dev/null; then
        start_spinner "Executando httpx (pode levar alguns minutos)..."
        cat "$subdomains_file" | httpx -silent -timeout 10 -retries 2 \
            -status-code -content-length -title \
            -o "$alive_details" 2>/dev/null
        stop_spinner

        # Extrair apenas URLs
        cat "$alive_details" | awk '{print $1}' | sort -u > "$alive_file"
    else
        log_error "httpx não encontrado! Instale com: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
        # Fallback: testar com curl
        while read -r sub; do
            for proto in https http; do
                if curl -s -o /dev/null -w "%{http_code}" "${proto}://${sub}" --max-time 5 2>/dev/null | grep -q "^[23]"; then
                    echo "${proto}://${sub}" >> "$alive_file"
                    break
                fi
            done
        done < "$subdomains_file"
    fi

    local total_alive=$(wc -l < "$alive_file" 2>/dev/null || echo "0")
    log_success "$total_alive hosts ativos"

    if [[ "$total_alive" -eq 0 ]]; then
        log_error "Nenhum host ativo encontrado!"
        return 1
    fi

    # Mostrar hosts ativos com detalhes
    echo ""
    if [[ -f "$alive_details" ]]; then
        head -15 "$alive_details" | while read -r line; do
            echo -e "  ${GREEN}✓${NC} $line"
        done
    else
        head -15 "$alive_file" | while read -r url; do
            echo -e "  ${GREEN}✓${NC} $url"
        done
    fi
    [[ $total_alive -gt 15 ]] && echo -e "  ${YELLOW}... e mais $((total_alive - 15)) hosts${NC}"

    # ========================================
    # FASE 3: FFUF - Fuzzing de Diretórios
    # ========================================
    log_phase "FASE 3: FUZZING COM FFUF" "4" "5"

    local scan_dir="${recon_dir}/scans"
    local current=0
    local success=0
    local failed=0

    # Calcular paralelismo inteligente baseado em recursos
    local cpu_cores=$(nproc 2>/dev/null || echo 4)
    local mem_gb=$(free -g 2>/dev/null | awk '/^Mem:/{print $7}' || echo 4)

    # Limitar jobs paralelos: min(cores/2, mem_gb, total_hosts, 6)
    local max_parallel=$((cpu_cores / 2))
    [[ $max_parallel -lt 2 ]] && max_parallel=2
    [[ $max_parallel -gt 6 ]] && max_parallel=6
    [[ $max_parallel -gt $total_alive ]] && max_parallel=$total_alive
    [[ $mem_gb -lt $max_parallel ]] && max_parallel=$mem_gb
    [[ $max_parallel -lt 1 ]] && max_parallel=1

    # Ajustar threads/rate por job quando paralelo
    local job_threads=$((threads / max_parallel))
    local job_rate=$((rate / max_parallel))
    [[ $job_threads -lt 5 ]] && job_threads=5
    [[ $job_rate -lt 10 ]] && job_rate=10

    # Preparar wordlists (diretório e API)
    create_api_wordlist 2>/dev/null
    local api_wordlist="${WORDLISTS_DIR}/api-master.txt"

    log_info "Iniciando ffuf em $total_alive hosts..."
    log_info "Configuração: ${GREEN}$max_parallel jobs paralelos${NC}, ${job_threads} threads/job, ${job_rate} req/s/job"
    log_info "Total rate: ~$((job_rate * max_parallel)) req/s | CPUs: $cpu_cores | Mem livre: ${mem_gb}GB"
    log_info "Wordlists: DIR=$(basename "$wordlist") | API=$(basename "$api_wordlist")"
    echo ""

    # Criar arquivo de controle de progresso
    local progress_file="${scan_dir}/.progress"
    echo "0" > "$progress_file"

    # Função para processar um único host (exportada para subshells)
    process_host() {
        local url="$1"
        local scan_dir="$2"
        local default_wordlist="$3"
        local job_threads="$4"
        local job_rate="$5"
        local timeout_val="$6"
        local maxtime="$7"
        local recursion_depth="$8"
        local total="$9"
        local progress_file="${10}"
        local api_wordlist="${11}"
        local wordlists_dir="${12}"

        local clean_name=$(echo "$url" | sed -E 's#^https?://##; s#[/:.]#_#g')
        local output_file="${scan_dir}/${clean_name}.json"
        local log_file="${scan_dir}/${clean_name}.log"

        # Incrementar progresso (atomic com flock para evitar race condition)
        local current
        if command -v flock &>/dev/null; then
            current=$(flock -x "$progress_file" bash -c 'c=$(<"$1"); echo $((c + 1)) > "$1"; echo $((c + 1))' _ "$progress_file")
        else
            current=$(cat "$progress_file" 2>/dev/null || echo 0)
            echo $((current + 1)) > "$progress_file"
            current=$((current + 1))
        fi

        # Detectar contexto (API vs Diretório normal)
        local subdomain=$(echo "$url" | sed -E 's#^https?://##; s#/.*##; s#:[0-9]+##')
        local path=$(echo "$url" | grep -oE '/[^?#]*' | head -1)
        local is_api=false
        local wordlist="$default_wordlist"
        local context_msg=""

        # Verificar se é contexto de API (inclui subdomínios de desenvolvimento)
        if echo "$subdomain" | grep -qiE '^(api[0-9]*|api-|apis|gateway|gw|graphql|rest|v[0-9]+|dev[0-9]*|stg|staging|prod|uat|qa|test|sandbox|internal)[-.]'; then
            is_api=true
        elif echo "$subdomain" | grep -qiE '(dev|stg|staging|prod|uat|qa|test)[-.]?api'; then
            is_api=true
        elif echo "$path" | grep -qiE '^/(api|apis|v[0-9]+|graphql|rest)/'; then
            is_api=true
        fi

        if $is_api && [[ -f "$api_wordlist" ]]; then
            wordlist="$api_wordlist"
            context_msg=" [API]"
        fi

        # Detectar WAF (rápido)
        local waf_check=$(curl -s -I "$url" --max-time 3 2>/dev/null | grep -i "cloudflare\|akamai\|incapsula" | head -1)
        local waf_msg=""
        if [[ -n "$waf_check" ]]; then
            waf_msg=" [WAF]"
            job_rate=$((job_rate / 2))
            job_threads=$((job_threads / 2))
            [[ $job_threads -lt 3 ]] && job_threads=3
            [[ $job_rate -lt 5 ]] && job_rate=5
        fi

        local wl_name=$(basename "$wordlist")
        echo -e "\033[0;36m[${current}/${total}]\033[0m \033[1;33m${url}\033[0m${context_msg}${waf_msg} → ${wl_name}"

        # Calibrar target para detectar catch-all
        local calibration_flags
        calibration_flags=$(calibrate_target "$url" 3)
        if [[ -n "$calibration_flags" ]]; then
            echo -e "  \033[0;33m⚠ Catch-all detectado → filtro: ${calibration_flags}\033[0m"
        fi

        # Executar FFUF
        if timeout $((maxtime + 30)) ffuf -c \
            -u "${url}/FUZZ" \
            -w "$wordlist" \
            -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
            -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
            -t "$job_threads" \
            -rate "$job_rate" \
            -timeout "$timeout_val" \
            -recursion \
            -recursion-depth "$recursion_depth" \
            -mc 200,201,204,301,302,307,308,401,403,405,500 \
            -fc 404 \
            -ac \
            $calibration_flags \
            -maxtime "$maxtime" \
            -maxtime-job 120 \
            -se \
            -sf \
            -o "$output_file" \
            -of json \
            > "$log_file" 2>&1; then

            # Contar resultados
            local results=$(python3 -c "import json; print(len(json.load(open('$output_file')).get('results', [])))" 2>/dev/null || echo "0")
            if [[ "$results" -gt 0 ]]; then
                echo -e "  \033[0;32m✓ $results resultados - ${url}\033[0m"
            fi
        else
            echo -e "  \033[0;31m✗ Timeout/Erro - ${url}\033[0m"
        fi
    }
    export -f calibrate_target
    export -f process_host

    # Executar em paralelo usando GNU parallel ou xargs
    if command -v parallel &>/dev/null; then
        log_info "Usando GNU parallel..."
        cat "$alive_file" | parallel -j "$max_parallel" --line-buffer \
            process_host {} "$scan_dir" "$wordlist" "$job_threads" "$job_rate" \
            "$DEFAULT_TIMEOUT" "$DEFAULT_MAXTIME" "$DEFAULT_RECURSION_DEPTH" \
            "$total_alive" "$progress_file" "$api_wordlist" "$WORDLISTS_DIR"
    else
        log_info "Usando xargs (instale 'parallel' para melhor performance)..."
        cat "$alive_file" | xargs -P "$max_parallel" -I {} bash -c \
            'process_host "$@"' _ {} "$scan_dir" "$wordlist" "$job_threads" "$job_rate" \
            "$DEFAULT_TIMEOUT" "$DEFAULT_MAXTIME" "$DEFAULT_RECURSION_DEPTH" \
            "$total_alive" "$progress_file" "$api_wordlist" "$WORDLISTS_DIR"
    fi

    # Filtrar falsos positivos e contar resultados finais
    log_info "Filtrando falsos positivos dos resultados..."
    for json_file in "${scan_dir}"/*.json; do
        [[ -f "$json_file" ]] || continue
        local raw_count=$(python3 -c "import json; print(len(json.load(open('$json_file')).get('results', [])))" 2>/dev/null || echo "0")
        if [[ "$raw_count" -gt 0 ]]; then
            filter_results "$json_file" >/dev/null 2>&1
            local filtered_file="${json_file%.json}_filtered.json"
            if [[ -f "$filtered_file" ]]; then
                cp "$filtered_file" "$json_file"
                rm -f "$filtered_file"
            fi
        fi
        local count=$(python3 -c "import json; print(len(json.load(open('$json_file')).get('results', [])))" 2>/dev/null || echo "0")
        [[ "$count" -gt 0 ]] && ((success++))
    done
    failed=$((total_alive - success))

    # ========================================
    # FASE 4: CONSOLIDAÇÃO E RELATÓRIO
    # ========================================
    log_phase "FASE 4: CONSOLIDAÇÃO DE RESULTADOS" "5" "5"

    local report_file="${recon_dir}/REPORT.md"
    local all_results="${recon_dir}/all_findings.txt"

    # Extrair todos os findings
    log_info "Consolidando resultados..."

    echo "# Recon Report - ${domain}" > "$report_file"
    echo "" >> "$report_file"
    echo "**Data:** $(date)" >> "$report_file"
    echo "**Modo:** ${mode}" >> "$report_file"
    echo "" >> "$report_file"
    echo "## Estatísticas" >> "$report_file"
    echo "" >> "$report_file"
    echo "- Subdomínios descobertos: $total_subs" >> "$report_file"
    echo "- Hosts ativos: $total_alive" >> "$report_file"
    echo "- Scans com sucesso: $success" >> "$report_file"
    echo "- Scans com falha: $failed" >> "$report_file"
    echo "" >> "$report_file"

    # Coletar todos os findings
    local total_findings=0
    echo "## Findings por Host" >> "$report_file"
    echo "" >> "$report_file"

    for json_file in "${scan_dir}"/*.json; do
        [[ -f "$json_file" ]] || continue

        local host=$(basename "$json_file" .json | sed 's/_/./g' | sed 's/^https\.\.//; s/^http\.\.//')
        local count=$(python3 -c "import json; print(len(json.load(open('$json_file')).get('results', [])))" 2>/dev/null || echo "0")

        if [[ "$count" -gt 0 ]]; then
            echo "### $host ($count findings)" >> "$report_file"
            echo "" >> "$report_file"

            # Listar URLs encontradas
            python3 -c "
import json
data = json.load(open('$json_file'))
for r in data.get('results', [])[:20]:
    url = r.get('url', '')
    status = r.get('status', 0)
    length = r.get('length', 0)
    print(f'- [{status}] {url} ({length} bytes)')
" 2>/dev/null >> "$report_file"

            echo "" >> "$report_file"
            ((total_findings += count))
        fi
    done

    # End phase timer for FASE 4
    [[ $PHASE_START_TIME -gt 0 ]] && end_phase_timer
    PHASE_START_TIME=0

    # Tempo total de execução
    local total_elapsed=$(( $(date +%s) - SCRIPT_START_TIME ))

    # Resumo final
    echo ""
    draw_line "top"
    box_center "RELATÓRIO FINAL"
    draw_line "mid"
    box_left "${CYAN}Domínio:${NC}              $domain"
    box_left "${CYAN}Subdomínios:${NC}          $total_subs"
    box_left "${CYAN}Hosts ativos:${NC}         $total_alive"
    box_left "${CYAN}Total de findings:${NC}    ${GREEN}$total_findings${NC}"
    draw_line "sep"
    box_left "${CYAN}Tempo total:${NC}          ${BOLD}$(format_elapsed $total_elapsed)${NC}"
    draw_line "sep"
    box_left "${CYAN}Arquivos gerados:${NC}"
    box_left "  • ${recon_dir}/subdomains.txt"
    box_left "  • ${recon_dir}/alive.txt"
    box_left "  • ${recon_dir}/scans/*.json"
    box_left "  • ${recon_dir}/REPORT.md"
    draw_line "bot"
    echo ""

    if [[ $total_findings -gt 0 ]]; then
        log_success "Recon completo! $total_findings endpoints encontrados."
    else
        log_warning "Recon completo. Nenhum endpoint interessante encontrado."
    fi

    echo -e "\n${CYAN}Diretório de resultados:${NC} ${recon_dir}"
}

# ============================================================================
# LOOT MODE - Deep scan: crawl + fuzz + file hunt + dirlist + report
# ============================================================================

# --- Helper: Crawl a single target with katana + gospider + gau ---
crawl_target() {
    local url="$1"
    local output_dir="$2"
    local host
    host=$(echo "$url" | sed -E 's#^https?://##; s#/.*##; s#:[0-9]+##')
    local domain
    domain=$(echo "$host" | sed -E 's/^[^.]+\.//' | grep -oE '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    [[ -z "$domain" ]] && domain="$host"

    mkdir -p "$output_dir"

    # katana — headless JS-aware crawling
    if command -v katana &>/dev/null; then
        katana -u "$url" -d 3 -jc -kf all -timeout 10 -silent -nc \
            -o "${output_dir}/${host}_katana.txt" >/dev/null 2>&1 &
    fi
    local pid_katana=$!

    # gospider — fast link spider
    if command -v gospider &>/dev/null; then
        gospider -s "$url" -d 2 -c 5 -t 1 --js --sitemap -q \
            -o "${output_dir}/gospider_${host}/" >/dev/null 2>&1 &
    fi
    local pid_gospider=$!

    # gau — historical URL fetch
    if command -v gau &>/dev/null; then
        echo "$domain" | gau --threads 3 -o "${output_dir}/${host}_gau.txt" >/dev/null 2>&1 &
    fi
    local pid_gau=$!

    # Wait for all crawlers
    wait $pid_katana 2>/dev/null
    wait $pid_gospider 2>/dev/null
    wait $pid_gau 2>/dev/null

    # Merge all output
    local all_urls="${output_dir}/${host}_all_urls.txt"
    local all_paths="${output_dir}/${host}_all_paths.txt"
    local files_found="${output_dir}/${host}_files_found.txt"

    {
        [[ -f "${output_dir}/${host}_katana.txt" ]] && cat "${output_dir}/${host}_katana.txt"
        [[ -d "${output_dir}/gospider_${host}" ]] && cat "${output_dir}/gospider_${host}/"* 2>/dev/null | grep -oE 'https?://[^ "'"'"'<>]+'
        [[ -f "${output_dir}/${host}_gau.txt" ]] && cat "${output_dir}/${host}_gau.txt"
    } | sort -u > "$all_urls" 2>/dev/null

    # Extract paths (same-domain only), deduplicate
    grep -iE "https?://(.*\.)?${domain//./\\.}" "$all_urls" 2>/dev/null \
        | sed -E 's#^https?://[^/]+##' | grep -E '^/' | sed 's/[?#].*//' \
        | sort -u > "$all_paths" 2>/dev/null

    # Extract interesting file URLs
    grep -iE '\.(pdf|doc|docx|xls|xlsx|csv|sql|bak|zip|tar\.gz|log|conf|xml|json|txt|env|sqlite|mdb|dump|7z|rar)(\?|$)' \
        "$all_urls" 2>/dev/null | sort -u > "$files_found" 2>/dev/null

    local url_count path_count file_count
    url_count=$(wc -l < "$all_urls" 2>/dev/null || echo 0)
    path_count=$(wc -l < "$all_paths" 2>/dev/null || echo 0)
    file_count=$(wc -l < "$files_found" 2>/dev/null || echo 0)

    echo "${host}|${url_count}|${path_count}|${file_count}"
}

# --- Helper: Detect directory listing ---
detect_dirlist() {
    local url="$1"
    local body
    body=$(curl -sk "$url" --max-time 8 2>/dev/null)
    [[ -z "$body" ]] && return 1

    if echo "$body" | grep -qiE 'Index of /|Parent Directory|\[DIR\]|Directory listing for|<title>Index of|ListBucketResult|EnumerationResults'; then
        echo "$body"
        return 0
    fi
    return 1
}

# --- Helper: Extract files from directory listing HTML ---
extract_dirlist_files() {
    local url="$1"
    local body="$2"
    local output_file="$3"

    # Extract href links from HTML
    echo "$body" | grep -oE 'href="[^"]*"' | sed 's/href="//;s/"$//' \
        | grep -vE '^\?|^/$|^\.\.' | while read -r link; do
        # Build absolute URL
        if [[ "$link" == http* ]]; then
            echo "$link"
        elif [[ "$link" == /* ]]; then
            local base
            base=$(echo "$url" | grep -oE '^https?://[^/]+')
            echo "${base}${link}"
        else
            echo "${url%/}/${link}"
        fi
    done | sort -u > "$output_file" 2>/dev/null
}

# --- Helper: Generate domain-specific filename wordlist ---
generate_file_wordlist() {
    local hostname="$1"
    local output_file="$2"
    local clean_host
    clean_host=$(echo "$hostname" | sed 's/[^a-zA-Z0-9]/_/g')

    local -a base_names=(
        "report" "invoice" "document" "backup" "data" "export" "users" "list"
        "manual" "guide" "policy" "contract" "resume" "cv" "budget" "plan"
        "log" "audit" "config" "admin" "internal" "confidential" "private"
        "archive" "database" "dump" "db" "credentials" "passwords" "keys"
        "accounts" "employees" "customers" "clients" "members" "staff"
        "financial" "payroll" "salary" "tax" "receipt" "statement"
        "readme" "changelog" "todo" "notes" "minutes" "agenda"
    )

    local -a extensions=(
        ".pdf" ".doc" ".docx" ".xls" ".xlsx" ".csv" ".sql" ".bak"
        ".zip" ".tar.gz" ".7z" ".rar" ".log" ".txt" ".xml" ".conf"
        ".dump" ".sqlite" ".mdb" ".json" ".yml" ".env"
    )

    local -a years=("2023" "2024" "2025" "2026")

    {
        # Base names + extensions
        for name in "${base_names[@]}"; do
            for ext in "${extensions[@]}"; do
                echo "${name}${ext}"
            done
        done

        # Year variants
        for name in "report" "backup" "data" "export" "audit" "log" "financial" "invoice" "budget"; do
            for year in "${years[@]}"; do
                for ext in ".pdf" ".xlsx" ".csv" ".sql" ".zip" ".bak"; do
                    echo "${name}-${year}${ext}"
                    echo "${name}_${year}${ext}"
                done
            done
        done

        # Domain-specific names
        for ext in ".sql" ".zip" ".bak" ".tar.gz" ".dump" ".pdf" ".csv"; do
            echo "${hostname}${ext}"
            echo "${clean_host}${ext}"
            echo "backup_${hostname}${ext}"
            echo "backup_${clean_host}${ext}"
            echo "${hostname}_backup${ext}"
            echo "${hostname}_dump${ext}"
            echo "${hostname}_db${ext}"
        done
    } | sort -u > "$output_file"
}

# --- Main loot_scan function ---
loot_scan() {
    local input="$1"
    local wordlist="${2:-auto}"
    local threads="${3:-60}"
    local rate="${4:-100}"

    if [[ -z "$input" ]]; then
        log_error "Uso: ./ffuf_master.sh --loot <hunt_dir|targets_file|url> [wordlist] [threads] [rate]"
        echo ""
        echo "Loot Mode: Deep scan com crawling + fuzzing + file hunting + dirlist detection"
        echo ""
        echo "Exemplos:"
        echo "  ./ffuf_master.sh --loot /root/ffuf_scans/results/redbull_hunt_20260211_*/"
        echo "  ./ffuf_master.sh --loot targets.txt"
        echo "  ./ffuf_master.sh --loot https://target.com"
        echo "  ./ffuf_master.sh --loot targets.txt auto 40 100"
        return 1
    fi

    # ===========================================================
    # PHASE 1: TARGET LOADING & CALIBRATION
    # ===========================================================
    log_phase "PHASE 1: TARGET LOADING & CALIBRATION" "1" "7"

    local -a targets=()
    local input_desc=""

    # Detect input type
    if [[ -d "$input" ]]; then
        # Directory — look for targets_no_waf.txt
        local nowaf_file="${input%/}/targets_no_waf.txt"
        if [[ -f "$nowaf_file" ]]; then
            while IFS= read -r line; do
                [[ -n "$line" ]] && targets+=("$line")
            done < "$nowaf_file"
            input_desc="Hunt dir: $(basename "${input%/}") (targets_no_waf.txt)"
        else
            log_error "Diretório não contém targets_no_waf.txt: $input"
            log_info "Procurando por arquivos de targets alternativos..."
            # Try alive.txt or any targets*.txt
            for f in "${input%/}"/alive.txt "${input%/}"/targets*.txt; do
                if [[ -f "$f" ]]; then
                    while IFS= read -r line; do
                        [[ -n "$line" ]] && targets+=("$line")
                    done < "$f"
                    input_desc="Hunt dir: $(basename "$f")"
                    break
                fi
            done
        fi
    elif [[ -f "$input" ]]; then
        # File — read URLs
        while IFS= read -r line; do
            [[ -n "$line" && "$line" != \#* ]] && targets+=("$line")
        done < "$input"
        input_desc="File: $(basename "$input")"
    elif [[ "$input" == http* ]]; then
        # Single URL
        targets+=("$input")
        input_desc="Single URL"
    else
        # Try adding https://
        targets+=("https://$input")
        input_desc="Single host"
    fi

    if [[ ${#targets[@]} -eq 0 ]]; then
        log_error "Nenhum target carregado do input: $input"
        return 1
    fi

    log_success "Carregados ${GREEN}${#targets[@]}${NC} targets"

    # Validate targets are alive with httpx
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local loot_dir="${RESULTS_DIR}/loot_${timestamp}"
    local crawl_dir="${loot_dir}/crawl"
    local fuzz_dir="${loot_dir}/fuzz"
    local files_dir="${loot_dir}/files"
    local dirlist_dir="${loot_dir}/dirlists"
    mkdir -p "$crawl_dir" "$fuzz_dir" "$files_dir" "$dirlist_dir"

    local alive_file="${loot_dir}/targets_alive.txt"

    if command -v httpx &>/dev/null && [[ ${#targets[@]} -gt 1 ]]; then
        log_info "Verificando targets vivos com httpx..."
        start_spinner "Checking targets..."
        printf '%s\n' "${targets[@]}" | httpx -silent -timeout 10 -threads 20 -nc > "$alive_file" 2>/dev/null
        stop_spinner
    else
        # Simple curl check
        log_info "Verificando targets vivos..."
        for url in "${targets[@]}"; do
            [[ "$url" != http* ]] && url="https://$url"
            local status
            status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$url" 2>/dev/null)
            if [[ "$status" != "000" ]]; then
                echo "$url" >> "$alive_file"
            fi
        done
    fi

    if [[ ! -s "$alive_file" ]]; then
        log_error "Nenhum target respondeu!"
        return 1
    fi

    # Reload alive targets
    targets=()
    while IFS= read -r line; do
        [[ -n "$line" ]] && targets+=("$line")
    done < "$alive_file"

    local target_count=${#targets[@]}
    log_success "${GREEN}${target_count}${NC} targets vivos"

    # WAF filtering for non-hunt-dir inputs
    if [[ ! -d "$input" ]]; then
        log_info "Filtrando targets com WAF/CDN..."
        local filtered_file="${loot_dir}/targets_no_waf.txt"
        local waf_file="${loot_dir}/targets_waf.txt"
        local cdn_file="${loot_dir}/targets_cdn.txt"

        # Criar arquivo temporário com todas as URLs
        local all_tmp="${loot_dir}/.all_targets_tmp.txt"
        printf '%s\n' "${targets[@]}" > "$all_tmp"

        bulk_cdn_check "$all_tmp" "$filtered_file" "$cdn_file" "$waf_file"
        rm -f "$all_tmp"

        # Log hosts protegidos
        if [[ -s "$waf_file" ]]; then
            while IFS= read -r line; do
                log_warning "WAF detectado, removendo: ${YELLOW}${line}${NC}"
            done < "$waf_file"
        fi
        if [[ -s "$cdn_file" ]]; then
            while IFS= read -r line; do
                log_warning "CDN detectado, removendo: ${BLUE}${line}${NC}"
            done < "$cdn_file"
        fi

        if [[ -s "$filtered_file" ]]; then
            cp "$filtered_file" "$alive_file"
            targets=()
            while IFS= read -r line; do
                [[ -n "$line" ]] && targets+=("$line")
            done < "$alive_file"
            target_count=${#targets[@]}
            log_success "${target_count} targets limpos para loot scan"
        fi
    fi

    # Calibrate each target
    log_info "Calibrando targets (catch-all detection)..."
    declare -A calibration_map
    local calibrated=0
    for url in "${targets[@]}"; do
        local host
        host=$(echo "$url" | sed -E 's#^https?://##; s#/.*##; s#:[0-9]+##')
        local flags
        flags=$(calibrate_target "$url" 5 2>/dev/null)
        calibration_map["$host"]="$flags"
        ((calibrated++))
        if [[ -n "$flags" ]]; then
            log_warning "Catch-all detectado em ${YELLOW}${host}${NC}: $flags"
        fi
        show_progress $calibrated $target_count "Calibrating"
    done

    # Display summary box
    echo ""
    draw_line "top"
    box_center "${BOLD}${MAGENTA}LOOT MODE${NC} ${BOLD}- FFUF MASTER v${SCRIPT_VERSION}${NC}"
    box_center "${RED}@${GREEN}ofj${YELLOW}aaah${NC}"
    draw_line "mid"
    box_left "Input:    ${YELLOW}${input_desc}${NC}"
    box_left "Targets:  ${GREEN}${target_count}${NC} alive (no WAF)"
    box_left "Strategy: ${MAGENTA}Crawl${NC} → ${RED}Fuzz${NC} → ${YELLOW}Files${NC} → ${CYAN}Dirlist${NC} → ${GREEN}Report${NC}"
    box_left "Threads:  ${threads} | Rate: ${rate}/s"
    box_left "Output:   ${loot_dir}"
    draw_line "bot"
    echo ""

    # ===========================================================
    # PHASE 2: WEB CRAWLING (katana + gospider + gau)
    # ===========================================================
    log_phase "PHASE 2: WEB CRAWLING (katana + gospider + gau)" "2" "7"

    local has_crawlers=false
    for tool in katana gospider gau; do
        command -v "$tool" &>/dev/null && has_crawlers=true && break
    done

    local total_crawl_urls=0
    local total_crawl_paths=0
    local total_crawl_files=0

    if $has_crawlers; then
        local crawl_progress=0
        for url in "${targets[@]}"; do
            local host
            host=$(echo "$url" | sed -E 's#^https?://##; s#/.*##; s#:[0-9]+##')
            ((crawl_progress++))
            log_info "[${crawl_progress}/${target_count}] Crawling ${CYAN}${host}${NC}..."
            start_spinner "Crawling ${host}..."

            local result
            result=$(crawl_target "$url" "$crawl_dir")
            stop_spinner

            local c_urls c_paths c_files
            c_urls=$(echo "$result" | tail -1 | cut -d'|' -f2)
            c_paths=$(echo "$result" | tail -1 | cut -d'|' -f3)
            c_files=$(echo "$result" | tail -1 | cut -d'|' -f4)
            c_urls=$((${c_urls:-0}))
            c_paths=$((${c_paths:-0}))
            c_files=$((${c_files:-0}))
            total_crawl_urls=$((total_crawl_urls + c_urls))
            total_crawl_paths=$((total_crawl_paths + c_paths))
            total_crawl_files=$((total_crawl_files + c_files))

            log_success "${host}: ${GREEN}${c_urls}${NC} URLs, ${c_paths} paths, ${c_files} files"
        done

        # Create global merged paths
        cat "${crawl_dir}"/*_all_paths.txt 2>/dev/null | sort -u > "${crawl_dir}/merged_paths.txt" 2>/dev/null
    else
        log_warning "Nenhum crawler instalado (katana/gospider/gau). Pulando fase de crawling."
        log_info "Instale: go install github.com/projectdiscovery/katana/cmd/katana@latest"
        touch "${crawl_dir}/merged_paths.txt"
    fi

    echo ""
    log_success "Crawling completo: ${GREEN}${total_crawl_urls}${NC} URLs, ${total_crawl_paths} paths, ${total_crawl_files} files"

    # ===========================================================
    # PHASE 3: SENSITIVE PATH FUZZING (ffuf)
    # ===========================================================
    log_phase "PHASE 3: SENSITIVE PATH FUZZING" "3" "7"

    # Build merged wordlist
    local merged_wordlist="${loot_dir}/wordlist_merged.txt"
    {
        # Base sensitive wordlist
        [[ -f "${WORDLISTS_DIR}/sensitive.txt" ]] && cat "${WORDLISTS_DIR}/sensitive.txt"
        # QuickHits
        [[ -f "${WORDLISTS_DIR}/quickhits.txt" ]] && cat "${WORDLISTS_DIR}/quickhits.txt"
        # Crawled paths
        [[ -s "${crawl_dir}/merged_paths.txt" ]] && cat "${crawl_dir}/merged_paths.txt"
    } | sed 's#^/##' | sort -u > "$merged_wordlist" 2>/dev/null

    # If no sensitive wordlist found, use default wordlist
    if [[ ! -s "$merged_wordlist" ]]; then
        local fallback_wl
        if [[ "$wordlist" != "auto" && -f "$wordlist" ]]; then
            fallback_wl="$wordlist"
        else
            fallback_wl=$(find_wordlist "" 2>/dev/null) || fallback_wl=""
        fi
        if [[ -n "$fallback_wl" && -f "$fallback_wl" ]]; then
            cp "$fallback_wl" "$merged_wordlist"
        else
            log_error "Nenhuma wordlist disponível para fuzzing!"
            log_warning "Execute: ./ffuf_master.sh --download-wordlists"
            return 1
        fi
    fi

    local wl_count
    wl_count=$(wc -l < "$merged_wordlist" 2>/dev/null || echo 0)
    log_info "Wordlist montada: ${GREEN}${wl_count}${NC} entradas"

    # Parallel fuzzing
    local cpu_cores
    cpu_cores=$(nproc 2>/dev/null || echo 4)
    local max_parallel=$((cpu_cores / 2))
    [[ $max_parallel -lt 2 ]] && max_parallel=2
    [[ $max_parallel -gt 4 ]] && max_parallel=4
    [[ $max_parallel -gt $target_count ]] && max_parallel=$target_count

    local job_threads=$((threads / max_parallel))
    local job_rate=$((rate / max_parallel))
    [[ $job_threads -lt 5 ]] && job_threads=5
    [[ $job_rate -lt 10 ]] && job_rate=10

    log_info "Fuzzing ${target_count} targets (${max_parallel} paralelos, ${job_threads} threads/job, ${job_rate} req/s/job)"

    local fuzz_progress=0
    for url in "${targets[@]}"; do
        local host
        host=$(echo "$url" | sed -E 's#^https?://##; s#/.*##; s#:[0-9]+##')
        ((fuzz_progress++))
        log_info "[${fuzz_progress}/${target_count}] Fuzzing ${CYAN}${host}${NC}..."

        local cal_flags="${calibration_map[$host]:-}"

        ffuf -u "${url%/}/FUZZ" -w "$merged_wordlist" \
            -t "$job_threads" -rate "$job_rate" \
            -mc 200,201,204,301,302,307,401,403,405 \
            -fc 404 -ac $cal_flags \
            -recursion -recursion-depth 2 \
            "${FFUF_HEADERS[@]}" \
            -timeout 10 -maxtime 300 -maxtime-job 120 \
            -o "${fuzz_dir}/fuzz_${host}.json" -of json -s 2>/dev/null

        # Post-filter
        if [[ -f "${fuzz_dir}/fuzz_${host}.json" ]]; then
            local raw
            raw=$(python3 -c "import json; print(len(json.load(open('${fuzz_dir}/fuzz_${host}.json')).get('results', [])))" 2>/dev/null || echo "0")
            if [[ "$raw" -gt 0 ]]; then
                filter_results "${fuzz_dir}/fuzz_${host}.json" >/dev/null 2>&1
                local filtered_file="${fuzz_dir}/fuzz_${host}_filtered.json"
                if [[ -f "$filtered_file" ]]; then
                    cp "$filtered_file" "${fuzz_dir}/fuzz_${host}.json"
                    rm -f "$filtered_file"
                fi
                local after
                after=$(python3 -c "import json; print(len(json.load(open('${fuzz_dir}/fuzz_${host}.json')).get('results', [])))" 2>/dev/null || echo "0")
                if [[ "$after" -gt 0 ]]; then
                    log_success "${host}: ${GREEN}${after}${NC} resultados (de ${raw} brutos)"
                else
                    log_info "${host}: 0 resultados (${raw} filtrados como FP)"
                fi
            else
                log_info "${host}: 0 resultados"
            fi
        fi
    done

    # ===========================================================
    # PHASE 4: FILE EXTENSION HUNTING
    # ===========================================================
    log_phase "PHASE 4: FILE EXTENSION HUNTING" "4" "7"

    # Generate filename wordlist per target
    local extensions_file="${loot_dir}/extensions.txt"
    cat > "$extensions_file" << 'EXTEOF'
.pdf
.doc
.docx
.xls
.xlsx
.csv
.sql
.bak
.zip
.tar.gz
.7z
.rar
.log
.txt
.xml
.conf
.dump
.sqlite
.mdb
EXTEOF

    local doc_paths=("documents" "docs" "files" "uploads" "media" "static" "assets" "public" "downloads" "attachments" "data" "reports" "content" "resources" "shared" "storage")

    local file_progress=0
    for url in "${targets[@]}"; do
        local host
        host=$(echo "$url" | sed -E 's#^https?://##; s#/.*##; s#:[0-9]+##')
        ((file_progress++))
        log_info "[${file_progress}/${target_count}] File hunting ${CYAN}${host}${NC}..."

        # Generate domain-specific filenames
        local filenames_file="${files_dir}/filenames_${host}.txt"
        generate_file_wordlist "$host" "$filenames_file"

        local cal_flags="${calibration_map[$host]:-}"

        # Clusterbomb: filename × extension
        ffuf -u "${url%/}/FUZZFUZ2Z" \
            -w "${filenames_file}:FUZZ" -w "${extensions_file}:FUZ2Z" \
            -mc 200 -ac $cal_flags \
            -t "$job_threads" -rate "$job_rate" \
            "${FFUF_HEADERS[@]}" \
            -timeout 10 -maxtime 300 \
            -o "${files_dir}/files_root_${host}.json" -of json -s 2>/dev/null

        # Fuzz common document directories
        for dpath in "${doc_paths[@]}"; do
            ffuf -u "${url%/}/${dpath}/FUZZFUZ2Z" \
                -w "${filenames_file}:FUZZ" -w "${extensions_file}:FUZ2Z" \
                -mc 200 -ac $cal_flags \
                -t "$job_threads" -rate "$job_rate" \
                "${FFUF_HEADERS[@]}" \
                -timeout 10 -maxtime 180 \
                -o "${files_dir}/files_${dpath}_${host}.json" -of json -s 2>/dev/null
        done

        # Count and report results
        local file_total=0
        for jf in "${files_dir}"/files_*_${host}.json; do
            [[ -f "$jf" ]] || continue
            local cnt
            cnt=$(python3 -c "import json; print(len(json.load(open('$jf')).get('results', [])))" 2>/dev/null || echo "0")
            file_total=$((file_total + cnt))
            # Filter each result file
            if [[ "$cnt" -gt 0 ]]; then
                filter_results "$jf" >/dev/null 2>&1
                local filt="${jf%.json}_filtered.json"
                [[ -f "$filt" ]] && cp "$filt" "$jf" && rm -f "$filt"
            fi
        done

        if [[ $file_total -gt 0 ]]; then
            log_success "${host}: ${GREEN}${file_total}${NC} arquivos encontrados"
        else
            log_info "${host}: 0 arquivos encontrados"
        fi
    done

    # ===========================================================
    # PHASE 5: DIRECTORY LISTING DETECTION
    # ===========================================================
    log_phase "PHASE 5: DIRECTORY LISTING DETECTION" "5" "7"

    local common_dirs=("img" "images" "uploads" "files" "media" "static" "assets" "backup" "backups" "data" "documents" "docs" "tmp" "temp" "cache" "logs" "reports" "export" "exports" "downloads" "attachments" "archive" "old" "public" "private" "internal" "share" "shared" "storage" "content" "resources" "lib" "css" "js" "fonts" "wp-content/uploads" "wp-includes")

    local total_open_dirs=0
    local dir_progress=0

    for url in "${targets[@]}"; do
        local host
        host=$(echo "$url" | sed -E 's#^https?://##; s#/.*##; s#:[0-9]+##')
        ((dir_progress++))
        log_info "[${dir_progress}/${target_count}] Checking dirlists on ${CYAN}${host}${NC}..."

        # Collect candidate dirs: common + from crawl + from fuzz results
        local -a candidate_dirs=()
        for d in "${common_dirs[@]}"; do
            candidate_dirs+=("$d")
        done

        # Add directories from crawl
        if [[ -f "${crawl_dir}/${host}_all_paths.txt" ]]; then
            while IFS= read -r p; do
                local dir_part
                dir_part=$(echo "$p" | sed 's#^/##; s#/[^/]*$##' | grep -v '^$')
                [[ -n "$dir_part" ]] && candidate_dirs+=("$dir_part")
            done < <(head -200 "${crawl_dir}/${host}_all_paths.txt")
        fi

        # Add directories from fuzz results (301/200 that look like dirs)
        if [[ -f "${fuzz_dir}/fuzz_${host}.json" ]]; then
            python3 -c "
import json, sys
try:
    data = json.load(open('${fuzz_dir}/fuzz_${host}.json'))
    for r in data.get('results', []):
        if r.get('status') in [200, 301, 302]:
            inp = r.get('input', {}).get('FUZZ', '')
            if inp and '.' not in inp.split('/')[-1]:
                print(inp)
except: pass
" 2>/dev/null | while IFS= read -r d; do
                candidate_dirs+=("$d")
            done
        fi

        # Deduplicate candidates
        local -a unique_dirs=()
        local -A seen_dirs=()
        for d in "${candidate_dirs[@]}"; do
            d="${d%/}"
            [[ -z "$d" ]] && continue
            if [[ -z "${seen_dirs[$d]+x}" ]]; then
                seen_dirs["$d"]=1
                unique_dirs+=("$d")
            fi
        done

        local host_open_dirs=0
        for dir in "${unique_dirs[@]}"; do
            local check_url="${url%/}/${dir}/"
            local body
            body=$(detect_dirlist "$check_url" 2>/dev/null)
            if [[ $? -eq 0 && -n "$body" ]]; then
                ((host_open_dirs++))
                ((total_open_dirs++))

                local dir_safe
                dir_safe=$(echo "$dir" | sed 's/[^a-zA-Z0-9]/_/g')
                local listing_file="${dirlist_dir}/dirlist_${host}_${dir_safe}.txt"

                extract_dirlist_files "$check_url" "$body" "$listing_file"
                local file_count
                file_count=$(wc -l < "$listing_file" 2>/dev/null || echo 0)

                log_success "${GREEN}OPEN DIR${NC}: ${check_url} (${file_count} files)"

                # Recurse into subdirectories (depth 1)
                if [[ $file_count -gt 0 ]]; then
                    while IFS= read -r sub_link; do
                        if [[ "$sub_link" == */ ]]; then
                            local sub_body
                            sub_body=$(detect_dirlist "$sub_link" 2>/dev/null)
                            if [[ $? -eq 0 && -n "$sub_body" ]]; then
                                local sub_safe
                                sub_safe=$(echo "${dir}_$(basename "${sub_link%/}")" | sed 's/[^a-zA-Z0-9]/_/g')
                                extract_dirlist_files "$sub_link" "$sub_body" "${dirlist_dir}/dirlist_${host}_${sub_safe}.txt"
                                local sub_count
                                sub_count=$(wc -l < "${dirlist_dir}/dirlist_${host}_${sub_safe}.txt" 2>/dev/null || echo 0)
                                log_success "  └─ ${sub_link} (${sub_count} files)"
                            fi
                        fi
                    done < "$listing_file"
                fi
            fi
        done

        if [[ $host_open_dirs -eq 0 ]]; then
            log_info "${host}: Nenhum directory listing encontrado"
        fi
    done

    echo ""
    log_success "Directory listing: ${GREEN}${total_open_dirs}${NC} diretórios abertos encontrados"

    # ===========================================================
    # PHASE 6: PDF & DOCUMENT VERIFICATION
    # ===========================================================
    log_phase "PHASE 6: PDF & DOCUMENT VERIFICATION" "6" "7"

    # Collect all file URLs from all phases
    local all_file_urls="${loot_dir}/all_file_urls_raw.txt"
    {
        # From crawl phase (files_found.txt per host)
        cat "${crawl_dir}"/*_files_found.txt 2>/dev/null

        # From fuzz phase (extract URLs from JSON results)
        for jf in "${files_dir}"/files_*.json "${fuzz_dir}"/fuzz_*.json; do
            [[ -f "$jf" ]] || continue
            python3 -c "
import json, sys
try:
    data = json.load(open('$jf'))
    for r in data.get('results', []):
        url = r.get('url', '')
        if url: print(url)
except: pass
" 2>/dev/null
        done

        # From dirlist extractions
        cat "${dirlist_dir}"/dirlist_*.txt 2>/dev/null
    } | sort -u > "$all_file_urls" 2>/dev/null

    local total_file_urls
    total_file_urls=$(wc -l < "$all_file_urls" 2>/dev/null || echo 0)
    log_info "Verificando ${total_file_urls} URLs de arquivos..."

    # Verify and categorize
    local verified_dir="${loot_dir}/verified"
    mkdir -p "$verified_dir"

    local pdfs="${verified_dir}/pdfs.txt"
    local documents="${verified_dir}/documents.txt"
    local spreadsheets="${verified_dir}/spreadsheets.txt"
    local databases="${verified_dir}/databases.txt"
    local backups="${verified_dir}/backups.txt"
    local configs="${verified_dir}/configs.txt"
    local logs_file="${verified_dir}/logs.txt"
    local other_files="${verified_dir}/other.txt"

    # Initialize files
    for f in "$pdfs" "$documents" "$spreadsheets" "$databases" "$backups" "$configs" "$logs_file" "$other_files"; do
        : > "$f"
    done

    local verified_count=0
    local verify_progress=0

    if [[ $total_file_urls -gt 0 ]]; then
        while IFS= read -r file_url; do
            ((verify_progress++))
            [[ $((verify_progress % 20)) -eq 0 ]] && show_progress $verify_progress $total_file_urls "Verifying"

            # HEAD request to verify
            local head_resp
            head_resp=$(curl -sk -I --max-time 5 "$file_url" 2>/dev/null)
            local http_status
            http_status=$(echo "$head_resp" | head -1 | grep -oE '[0-9]{3}' | head -1)

            [[ "$http_status" != "200" ]] && continue

            local content_type
            content_type=$(echo "$head_resp" | grep -i "^content-type:" | head -1 | tr -d '\r' | awk '{print $2}')
            local content_length
            content_length=$(echo "$head_resp" | grep -i "^content-length:" | head -1 | tr -d '\r' | awk '{print $2}')
            local last_modified
            last_modified=$(echo "$head_resp" | grep -i "^last-modified:" | head -1 | sed 's/^[^:]*: //' | tr -d '\r')

            ((verified_count++))
            local info_line="${file_url}|${content_length:-unknown}|${content_type:-unknown}|${last_modified:-unknown}"

            # Categorize
            case "$file_url" in
                *.pdf)                              echo "$info_line" >> "$pdfs" ;;
                *.doc|*.docx|*.odt)                 echo "$info_line" >> "$documents" ;;
                *.xls|*.xlsx|*.csv)                 echo "$info_line" >> "$spreadsheets" ;;
                *.sql|*.sqlite|*.mdb|*.dump)        echo "$info_line" >> "$databases" ;;
                *.zip|*.tar.gz|*.bak|*.7z|*.rar)    echo "$info_line" >> "$backups" ;;
                *.conf|*.env|*.yml|*.yaml|*.json|*.xml) echo "$info_line" >> "$configs" ;;
                *.log)                              echo "$info_line" >> "$logs_file" ;;
                *)
                    # Categorize by content-type
                    case "$content_type" in
                        *pdf*)          echo "$info_line" >> "$pdfs" ;;
                        *spreadsheet*|*excel*|*csv*)  echo "$info_line" >> "$spreadsheets" ;;
                        *msword*|*document*)  echo "$info_line" >> "$documents" ;;
                        *sql*|*sqlite*)  echo "$info_line" >> "$databases" ;;
                        *zip*|*gzip*|*compressed*)  echo "$info_line" >> "$backups" ;;
                        *)              echo "$info_line" >> "$other_files" ;;
                    esac
                    ;;
            esac
        done < "$all_file_urls"
    fi

    echo ""
    local pdf_count doc_count sheet_count db_count bak_count conf_count log_count other_count
    pdf_count=$(wc -l < "$pdfs" 2>/dev/null || echo 0)
    doc_count=$(wc -l < "$documents" 2>/dev/null || echo 0)
    sheet_count=$(wc -l < "$spreadsheets" 2>/dev/null || echo 0)
    db_count=$(wc -l < "$databases" 2>/dev/null || echo 0)
    bak_count=$(wc -l < "$backups" 2>/dev/null || echo 0)
    conf_count=$(wc -l < "$configs" 2>/dev/null || echo 0)
    log_count=$(wc -l < "$logs_file" 2>/dev/null || echo 0)
    other_count=$(wc -l < "$other_files" 2>/dev/null || echo 0)

    log_success "Verificados: ${GREEN}${verified_count}${NC} arquivos confirmados"
    [[ $pdf_count -gt 0 ]]   && log_success "  PDFs:          ${GREEN}${pdf_count}${NC}"
    [[ $doc_count -gt 0 ]]   && log_success "  Documents:     ${GREEN}${doc_count}${NC}"
    [[ $sheet_count -gt 0 ]] && log_success "  Spreadsheets:  ${GREEN}${sheet_count}${NC}"
    [[ $db_count -gt 0 ]]    && log_success "  Databases:     ${RED}${db_count}${NC}"
    [[ $bak_count -gt 0 ]]   && log_success "  Backups:       ${RED}${bak_count}${NC}"
    [[ $conf_count -gt 0 ]]  && log_success "  Configs:       ${YELLOW}${conf_count}${NC}"
    [[ $log_count -gt 0 ]]   && log_success "  Logs:          ${YELLOW}${log_count}${NC}"
    [[ $other_count -gt 0 ]] && log_info    "  Other:         ${other_count}"

    # ===========================================================
    # PHASE 7: CONSOLIDATION + REPORT
    # ===========================================================
    log_phase "PHASE 7: CONSOLIDATION & REPORT" "7" "7"

    # Flat list of all findings
    local all_findings="${loot_dir}/all_findings.txt"
    {
        # From fuzz results
        for jf in "${fuzz_dir}"/fuzz_*.json; do
            [[ -f "$jf" ]] || continue
            python3 -c "
import json
try:
    data = json.load(open('$jf'))
    for r in data.get('results', []):
        url = r.get('url', '')
        status = r.get('status', 0)
        length = r.get('length', 0)
        if url: print(f'{status} {length}b {url}')
except: pass
" 2>/dev/null
        done

        # From file results
        for jf in "${files_dir}"/files_*.json; do
            [[ -f "$jf" ]] || continue
            python3 -c "
import json
try:
    data = json.load(open('$jf'))
    for r in data.get('results', []):
        url = r.get('url', '')
        status = r.get('status', 0)
        length = r.get('length', 0)
        if url: print(f'{status} {length}b {url}')
except: pass
" 2>/dev/null
        done
    } | sort -u > "$all_findings" 2>/dev/null

    # Simplified output files
    cut -d'|' -f1 "$pdfs" 2>/dev/null > "${loot_dir}/pdfs.txt"
    cut -d'|' -f1 "$documents" 2>/dev/null > "${loot_dir}/documents.txt"
    {
        cat "${dirlist_dir}"/dirlist_*.txt 2>/dev/null
    } | sort -u > "${loot_dir}/open_dirs.txt" 2>/dev/null

    # Count total findings
    local total_fuzz_findings=0
    for jf in "${fuzz_dir}"/fuzz_*.json; do
        [[ -f "$jf" ]] || continue
        local cnt
        cnt=$(python3 -c "import json; print(len(json.load(open('$jf')).get('results', [])))" 2>/dev/null || echo "0")
        total_fuzz_findings=$((total_fuzz_findings + cnt))
    done

    local total_file_findings=0
    for jf in "${files_dir}"/files_*.json; do
        [[ -f "$jf" ]] || continue
        local cnt
        cnt=$(python3 -c "import json; print(len(json.load(open('$jf')).get('results', [])))" 2>/dev/null || echo "0")
        total_file_findings=$((total_file_findings + cnt))
    done

    # Generate LOOT_REPORT.md
    local report="${loot_dir}/LOOT_REPORT.md"
    local total_elapsed=$(( $(date +%s) - SCRIPT_START_TIME ))

    cat > "$report" << REPORTEOF
# Loot Report
**Generated:** $(date '+%Y-%m-%d %H:%M:%S')
**Duration:** $(format_elapsed $total_elapsed)
**FFUF Master:** v${SCRIPT_VERSION}

---

## Target Summary
- **Targets scanned:** ${target_count} (no WAF/CDN)
- **Input:** ${input_desc}

| Target | Calibration |
|--------|------------|
REPORTEOF

    for url in "${targets[@]}"; do
        local host
        host=$(echo "$url" | sed -E 's#^https?://##; s#/.*##; s#:[0-9]+##')
        local cal="${calibration_map[$host]:-none}"
        [[ -z "$cal" ]] && cal="clean (no catch-all)"
        echo "| ${url} | ${cal} |" >> "$report"
    done

    cat >> "$report" << REPORTEOF

---

## Crawling Results (katana/gospider/gau)
- **Total URLs discovered:** ${total_crawl_urls}
- **Unique paths extracted:** ${total_crawl_paths}
- **Files found in crawl:** ${total_crawl_files}

REPORTEOF

    # Crawl details per host
    for url in "${targets[@]}"; do
        local host
        host=$(echo "$url" | sed -E 's#^https?://##; s#/.*##; s#:[0-9]+##')
        local uc pc fc
        uc=$(wc -l < "${crawl_dir}/${host}_all_urls.txt" 2>/dev/null || echo 0)
        pc=$(wc -l < "${crawl_dir}/${host}_all_paths.txt" 2>/dev/null || echo 0)
        fc=$(wc -l < "${crawl_dir}/${host}_files_found.txt" 2>/dev/null || echo 0)
        echo "- **${host}**: ${uc} URLs, ${pc} paths, ${fc} files" >> "$report"
    done

    cat >> "$report" << REPORTEOF

---

## Sensitive Paths Found (ffuf)
- **Total findings:** ${total_fuzz_findings}

REPORTEOF

    for jf in "${fuzz_dir}"/fuzz_*.json; do
        [[ -f "$jf" ]] || continue
        python3 -c "
import json
try:
    data = json.load(open('$jf'))
    results = data.get('results', [])
    if results:
        for r in sorted(results, key=lambda x: x.get('status', 0)):
            url = r.get('url', '')
            status = r.get('status', 0)
            length = r.get('length', 0)
            words = r.get('words', 0)
            print(f'- [{status}] {url} ({length}b, {words}w)')
except: pass
" 2>/dev/null >> "$report"
    done

    cat >> "$report" << REPORTEOF

---

## Documents & Files Found
- **Total file findings:** ${total_file_findings}
- **Verified files:** ${verified_count}

### PDFs (${pdf_count})
REPORTEOF
    [[ -s "$pdfs" ]] && while IFS='|' read -r furl fsize ftype fmod; do
        echo "- [${fsize:-?}b] ${furl}" >> "$report"
    done < "$pdfs"

    cat >> "$report" << REPORTEOF

### Documents (${doc_count})
REPORTEOF
    [[ -s "$documents" ]] && while IFS='|' read -r furl fsize ftype fmod; do
        echo "- [${fsize:-?}b] ${furl}" >> "$report"
    done < "$documents"

    cat >> "$report" << REPORTEOF

### Spreadsheets (${sheet_count})
REPORTEOF
    [[ -s "$spreadsheets" ]] && while IFS='|' read -r furl fsize ftype fmod; do
        echo "- [${fsize:-?}b] ${furl}" >> "$report"
    done < "$spreadsheets"

    cat >> "$report" << REPORTEOF

### Database Dumps (${db_count})
REPORTEOF
    [[ -s "$databases" ]] && while IFS='|' read -r furl fsize ftype fmod; do
        echo "- [${fsize:-?}b] **${furl}**" >> "$report"
    done < "$databases"

    cat >> "$report" << REPORTEOF

### Backup Files (${bak_count})
REPORTEOF
    [[ -s "$backups" ]] && while IFS='|' read -r furl fsize ftype fmod; do
        echo "- [${fsize:-?}b] **${furl}**" >> "$report"
    done < "$backups"

    cat >> "$report" << REPORTEOF

### Config Files (${conf_count})
REPORTEOF
    [[ -s "$configs" ]] && while IFS='|' read -r furl fsize ftype fmod; do
        echo "- [${fsize:-?}b] **${furl}**" >> "$report"
    done < "$configs"

    cat >> "$report" << REPORTEOF

### Log Files (${log_count})
REPORTEOF
    [[ -s "$logs_file" ]] && while IFS='|' read -r furl fsize ftype fmod; do
        echo "- [${fsize:-?}b] ${furl}" >> "$report"
    done < "$logs_file"

    cat >> "$report" << REPORTEOF

---

## Open Directory Listings (${total_open_dirs})
REPORTEOF

    if [[ $total_open_dirs -gt 0 ]]; then
        for listing in "${dirlist_dir}"/dirlist_*.txt; do
            [[ -f "$listing" ]] || continue
            local lname
            lname=$(basename "$listing" .txt | sed 's/^dirlist_//')
            local lcount
            lcount=$(wc -l < "$listing" 2>/dev/null || echo 0)
            echo "### ${lname} (${lcount} files)" >> "$report"
            head -20 "$listing" 2>/dev/null | while read -r lurl; do
                echo "- ${lurl}" >> "$report"
            done
            [[ $lcount -gt 20 ]] && echo "- ... and $((lcount - 20)) more" >> "$report"
            echo "" >> "$report"
        done
    else
        echo "_No open directory listings found._" >> "$report"
    fi

    cat >> "$report" << REPORTEOF

---

## Summary
| Category | Count |
|----------|-------|
| Targets scanned | ${target_count} |
| URLs crawled | ${total_crawl_urls} |
| Sensitive paths found | ${total_fuzz_findings} |
| Files found (extension hunt) | ${total_file_findings} |
| Verified documents | ${verified_count} |
| Open directory listings | ${total_open_dirs} |
| **Total scan time** | **$(format_elapsed $total_elapsed)** |
REPORTEOF

    # Final summary box
    echo ""
    draw_line "top"
    box_center "${BOLD}${MAGENTA}LOOT REPORT${NC}"
    draw_line "mid"
    box_left "${CYAN}Targets:${NC}              ${target_count}"
    box_left "${CYAN}URLs crawled:${NC}         ${total_crawl_urls}"
    box_left "${CYAN}Sensitive paths:${NC}      ${GREEN}${total_fuzz_findings}${NC}"
    box_left "${CYAN}Files found:${NC}          ${GREEN}${total_file_findings}${NC}"
    box_left "${CYAN}Verified documents:${NC}   ${GREEN}${verified_count}${NC}"
    box_left "${CYAN}Open directories:${NC}     ${GREEN}${total_open_dirs}${NC}"
    draw_line "sep"
    box_left "${CYAN}Tempo total:${NC}          ${BOLD}$(format_elapsed $total_elapsed)${NC}"
    draw_line "sep"
    box_left "${CYAN}Arquivos gerados:${NC}"
    box_left "  • ${loot_dir}/LOOT_REPORT.md"
    box_left "  • ${loot_dir}/all_findings.txt"
    box_left "  • ${loot_dir}/pdfs.txt"
    box_left "  • ${loot_dir}/documents.txt"
    box_left "  • ${loot_dir}/open_dirs.txt"
    draw_line "bot"
    echo ""

    local grand_total=$((total_fuzz_findings + total_file_findings + verified_count + total_open_dirs))
    if [[ $grand_total -gt 0 ]]; then
        log_success "Loot scan completo! ${GREEN}${grand_total}${NC} achados totais."
    else
        log_warning "Loot scan completo. Nenhum achado significativo."
    fi

    echo -e "\n${CYAN}Diretório de resultados:${NC} ${loot_dir}"
    echo -e "${CYAN}Relatório:${NC} ${loot_dir}/LOOT_REPORT.md"
}

# ============================================================================
# SCAN DE SITE ÚNICO (SEM ENUMERAÇÃO DE SUBDOMÍNIOS)
# ============================================================================

single_site_scan() {
    local url="$1"
    local wordlist="$2"
    local threads="${3:-$DEFAULT_THREADS}"
    local rate="${4:-$DEFAULT_RATE}"
    local mode="${5:-normal}"

    if [[ -z "$url" ]]; then
        log_error "Uso: ./ffuf_master.sh <url> [wordlist] [threads] [rate] [mode]"
        echo ""
        echo "Exemplos:"
        echo "  ./ffuf_master.sh https://target.com"
        echo "  ./ffuf_master.sh https://target.com/api /path/to/wordlist.txt"
        echo "  ./ffuf_master.sh https://target.com auto 40 100 stealth"
        return 1
    fi

    # Adicionar protocolo se não tiver
    [[ "$url" != http* ]] && url="https://$url"
    url="${url%/}"

    # Encontrar wordlist (auto-detecta API vs DIR)
    if [[ -z "$wordlist" || "$wordlist" == "auto" ]]; then
        wordlist=$(select_smart_wordlist "$url")
    else
        wordlist=$(find_wordlist "$wordlist") || return 1
    fi

    # Ajustar configurações por modo
    case "$mode" in
        stealth)
            threads=5
            rate=10
            log_warning "Modo STEALTH ativado (lento, para WAF)"
            ;;
        aggressive)
            threads=50
            rate=150
            log_warning "Modo AGGRESSIVE ativado (rápido, pode causar bloqueio)"
            ;;
    esac

    # Criar diretório de resultados
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local clean_name=$(echo "$url" | sed -E 's#^https?://##; s#[/:.]#_#g')
    local scan_dir="${RESULTS_DIR}/${clean_name}_${timestamp}"
    mkdir -p "$scan_dir"

    echo ""
    draw_line "top"
    box_center "FFUF MASTER - SINGLE SITE SCAN v${SCRIPT_VERSION}"
    box_center "${RED}@${GREEN}ofj${YELLOW}aaah${NC}"
    draw_line "mid"
    box_left "Target:   ${YELLOW}${url}${NC}"
    box_left "Mode:     ${GREEN}${mode}${NC} | Threads: ${threads} | Rate: ${rate}/s"
    box_left "Wordlist: $(basename "$wordlist") ($(wc -l < "$wordlist") palavras)"
    box_left "Output:   ${scan_dir}"
    draw_line "bot"
    echo ""

    # Detectar CDN/WAF via cdncheck
    start_spinner "Detectando CDN/WAF..."
    local cdn_provider
    cdn_provider=$(detect_cdn_waf "$url" 2>/dev/null)
    local waf_status=$?
    stop_spinner

    case $waf_status in
        1)
            log_error "BLOQUEIO ATIVO detectado! Considere usar modo stealth ou VPN."
            return 1
            ;;
        2)
            log_error "WAF Detectado: ${RED}${cdn_provider}${NC} — scan cancelado (host protegido)"
            log_info "Use 'bypass' para testar bypass de 403: ./ffuf_master.sh bypass $url"
            return 1
            ;;
        3)
            log_error "CDN Detectado: ${BLUE}${cdn_provider}${NC} — scan cancelado (host atrás de CDN)"
            log_info "Scans em CDN geram falsos positivos e podem ser bloqueados."
            return 1
            ;;
        4)
            log_warning "Cloud Provider: ${CYAN}${cdn_provider}${NC} — continuando com rate reduzido"
            rate=$((rate / 2))
            [[ $rate -lt 10 ]] && rate=10
            ;;
    esac

    # Detectar contexto (API vs Diretório)
    local context_msg=""
    if is_api_context "$url"; then
        context_msg=" [API Context]"
        log_info "Contexto de API detectado - usando wordlist apropriada"
    fi

    log_phase "FUZZING${context_msg}"

    local output_file="${scan_dir}/results.json"
    local output_txt="${scan_dir}/results.txt"

    # Calibrar target para detectar catch-all
    start_spinner "Calibrando target..."
    local calibration_flags
    calibration_flags=$(calibrate_target "$url" 5)
    stop_spinner

    if [[ -n "$calibration_flags" ]]; then
        log_warning "Catch-all detectado! Filtro automático: ${BOLD}${calibration_flags}${NC}"
    else
        log_info "Target OK - sem catch-all detectado"
    fi

    log_info "Executando ffuf em ${url}..."
    echo ""

    # Executar FFUF
    if ffuf -c \
        -u "${url}/FUZZ" \
        -w "$wordlist" \
        "${FFUF_HEADERS[@]}" \
        -t "$threads" \
        -rate "$rate" \
        -timeout "$DEFAULT_TIMEOUT" \
        -recursion \
        -recursion-depth "$DEFAULT_RECURSION_DEPTH" \
        -mc 200,201,204,301,302,307,308,401,403,405,500 \
        -fc 404 \
        -ac \
        $calibration_flags \
        -maxtime "$DEFAULT_MAXTIME" \
        -maxtime-job 120 \
        -se \
        -sf \
        -o "$output_file" \
        -of json 2>&1; then

        # Processar resultados
        if [[ -f "$output_file" ]]; then
            # Auto-filter false positives
            local raw_results=$(python3 -c "import json; print(len(json.load(open('$output_file')).get('results', [])))" 2>/dev/null || echo "0")
            if [[ "$raw_results" -gt 0 ]]; then
                local filter_output
                filter_output=$(filter_results "$output_file" 2>&1)
                local filtered_file="${output_file%.json}_filtered.json"
                if [[ -f "$filtered_file" ]]; then
                    log_info "$filter_output"
                    cp "$filtered_file" "$output_file"
                    rm -f "$filtered_file"
                fi
            fi

            local results=$(python3 -c "import json; print(len(json.load(open('$output_file')).get('results', [])))" 2>/dev/null || echo "0")

            echo ""
            log_phase "RESULTADOS"

            if [[ "$results" -gt 0 ]]; then
                log_success "$results endpoints encontrados!"
                echo ""

                # Cabeçalho da tabela
                printf "  ${BOLD}%-6s %-60s %s${NC}\n" "STATUS" "URL" "TAMANHO"
                printf "  ${CYAN}%-6s %-60s %s${NC}\n" "──────" "────────────────────────────────────────────────────────────" "────────"

                # Extrair e mostrar resultados formatados
                python3 -c "
import json
data = json.load(open('$output_file'))
for r in data.get('results', []):
    url = r.get('url', '')
    status = r.get('status', 0)
    length = r.get('length', 0)
    print(f'{status}|{url}|{length}')
" 2>/dev/null | while IFS='|' read -r status url length; do
                    format_result "$status" "$url" "${length} bytes"
                    echo "$status $url ($length bytes)" >> "$output_txt"
                done

                echo ""
                log_info "Resultados salvos em:"
                echo -e "  • ${scan_dir}/results.json"
                echo -e "  • ${scan_dir}/results.txt"
            else
                log_warning "Nenhum endpoint encontrado."
            fi
        fi
    else
        log_error "Erro ao executar ffuf"
        return 1
    fi

    echo ""
    log_success "Scan completo!"
}

# ============================================================================
# FUNÇÕES AUXILIARES DE SCAN
# ============================================================================

# Scan rápido em URL única
quick_scan() {
    local url="$1"
    local wordlist
    if [[ -n "$2" ]]; then
        wordlist=$(find_wordlist "$2") || return 1
    else
        wordlist=$(select_smart_wordlist "$url")
    fi

    log_info "Quick scan em: $url"

    local calibration_flags
    calibration_flags=$(calibrate_target "$url" 3)
    [[ -n "$calibration_flags" ]] && log_warning "Catch-all detectado → filtro: ${calibration_flags}"

    ffuf -c \
        -u "${url}/FUZZ" \
        -w "$wordlist" \
        "${FFUF_HEADERS[@]}" \
        -t 30 \
        -rate 50 \
        -timeout 10 \
        -mc 200,201,204,301,302,307,401,403,405,500 \
        -fc 404 \
        -ac \
        $calibration_flags
}

# Scan stealth (para WAFs)
stealth_scan() {
    local url="$1"
    local wordlist
    if [[ -n "$2" ]]; then
        wordlist=$(find_wordlist "$2") || return 1
    else
        wordlist=$(select_smart_wordlist "$url")
    fi

    log_warning "Modo STEALTH: 5 req/s, delays aleatórios"

    local calibration_flags
    calibration_flags=$(calibrate_target "$url" 3)
    [[ -n "$calibration_flags" ]] && log_warning "Catch-all detectado → filtro: ${calibration_flags}"

    ffuf -c \
        -u "${url}/FUZZ" \
        -w "$wordlist" \
        "${FFUF_HEADERS[@]}" \
        -t 1 \
        -rate 5 \
        -timeout 20 \
        -p "0.5-2.0" \
        -mc all \
        -fc 404 \
        -ac \
        $calibration_flags
}

# ============================================================================
# FILTRO DE FALSOS POSITIVOS
# ============================================================================

# Patterns conhecidos de falsos positivos
FP_PATTERNS=(
    '^\.[a-z]+\.txt$'      # .mysql.txt, .pgsql.txt (wildcard catch-all)
    '^\.[a-z]+$'           # .txt, .pdf, .swf (extensões sem nome)
    '^\.ht'                # .htaccess, .htpasswd (geralmente bloqueados)
    'favicon'
    'robots\.txt'
)

# Calibrar target para detectar catch-all responses (soft-404)
# Retorna ffuf filter flags (-fl/-fw/-fs) ou string vazia se target é normal
calibrate_target() {
    local url="$1"
    local num_probes="${2:-5}"  # 5 por padrão, 3 para quick/stealth

    # Gerar paths aleatórios de comprimentos variados
    local -a probe_paths=()
    local lengths=(8 12 16 24 32)
    for i in $(seq 1 "$num_probes"); do
        local len=${lengths[$((i - 1))]}
        [[ -z "$len" ]] && len=16
        probe_paths+=("$(head /dev/urandom | tr -dc 'a-z0-9' | head -c "$len")")
    done

    local -a statuses=()
    local -a sizes=()
    local -a words=()
    local -a lines=()

    for path in "${probe_paths[@]}"; do
        local resp
        resp=$(curl -s -o /tmp/.calibrate_body -w "%{http_code}|%{size_download}" \
            -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0" \
            --max-time 5 "${url%/}/${path}" 2>/dev/null)

        local code size wc lc
        code=$(echo "$resp" | cut -d'|' -f1)
        size=$(echo "$resp" | cut -d'|' -f2)
        wc=0; lc=0
        if [[ -f /tmp/.calibrate_body ]]; then
            wc=$(wc -w < /tmp/.calibrate_body 2>/dev/null || echo 0)
            lc=$(wc -l < /tmp/.calibrate_body 2>/dev/null || echo 0)
        fi

        statuses+=("$code")
        sizes+=("$size")
        words+=("$wc")
        lines+=("$lc")
    done
    rm -f /tmp/.calibrate_body

    # Check: are all responses the same status and NOT 404?
    local first_status="${statuses[0]}"
    local all_same_status=true
    for s in "${statuses[@]}"; do
        [[ "$s" != "$first_status" ]] && all_same_status=false && break
    done

    # If responses are 404, target is behaving normally
    if [[ "$first_status" == "404" ]] && $all_same_status; then
        echo ""
        return 0
    fi

    # If not all same status, no consistent catch-all
    if ! $all_same_status; then
        echo ""
        return 0
    fi

    # All returned same non-404 status → possible catch-all
    # Check if metrics are similar (within tolerance)

    # Helper: check if all values in array are within ±tolerance of median
    _values_clustered() {
        local -a vals=("$@")
        local n=${#vals[@]}
        [[ $n -lt 2 ]] && return 0

        # Sort to find median
        local -a sorted
        IFS=$'\n' sorted=($(printf '%s\n' "${vals[@]}" | sort -n)); unset IFS
        local median=${sorted[$((n / 2))]}
        [[ $median -eq 0 ]] && median=1

        # Tolerance: ±5% or ±50, whichever is larger
        local pct_tol=$(( median * 5 / 100 ))
        local tol=$pct_tol
        [[ $tol -lt 50 ]] && tol=50

        for v in "${vals[@]}"; do
            local diff=$(( v - median ))
            [[ $diff -lt 0 ]] && diff=$(( -diff ))
            [[ $diff -gt $tol ]] && return 1
        done
        return 0
    }

    # Try lines first (most stable — path reflected in body doesn't change line count)
    if _values_clustered "${lines[@]}"; then
        local -a sorted_lines
        IFS=$'\n' sorted_lines=($(printf '%s\n' "${lines[@]}" | sort -n)); unset IFS
        local median_lines=${sorted_lines[$(( ${#sorted_lines[@]} / 2 ))]}
        if [[ $median_lines -gt 0 ]]; then
            echo "-fl $median_lines"
            return 0
        fi
    fi

    # Try words (second most stable)
    if _values_clustered "${words[@]}"; then
        local -a sorted_words
        IFS=$'\n' sorted_words=($(printf '%s\n' "${words[@]}" | sort -n)); unset IFS
        local median_words=${sorted_words[$(( ${#sorted_words[@]} / 2 ))]}
        if [[ $median_words -gt 0 ]]; then
            echo "-fw $median_words"
            return 0
        fi
    fi

    # Fallback: size with range filter (min-max)
    if _values_clustered "${sizes[@]}"; then
        local -a sorted_sizes
        IFS=$'\n' sorted_sizes=($(printf '%s\n' "${sizes[@]}" | sort -n)); unset IFS
        local min_size=${sorted_sizes[0]}
        local max_size=${sorted_sizes[$(( ${#sorted_sizes[@]} - 1 ))]}
        # Add 10% margin on each side
        local margin=$(( (max_size - min_size) / 2 + 50 ))
        local fs_min=$(( min_size - margin ))
        local fs_max=$(( max_size + margin ))
        [[ $fs_min -lt 0 ]] && fs_min=0
        echo "-fs ${fs_min}-${fs_max}"
        return 0
    fi

    # Metrics vary too much — not a simple catch-all
    echo ""
    return 0
}

# Verificar se é falso positivo baseado em comparação de conteúdo
verify_finding() {
    local url="$1"
    local expected_status="$2"
    local expected_length="$3"

    # Fazer request real e comparar
    local response=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" \
        -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0" \
        --max-time 10 "$url" 2>/dev/null)

    local real_status=$(echo "$response" | cut -d'|' -f1)
    local real_length=$(echo "$response" | cut -d'|' -f2)

    # Verificar se é catch-all (mesmo conteúdo para qualquer path)
    local random_path="${url%/*}/$(head /dev/urandom | tr -dc 'a-z0-9' | head -c 16)"
    local random_response=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" \
        -H "User-Agent: Mozilla/5.0" --max-time 5 "$random_path" 2>/dev/null)
    local random_length=$(echo "$random_response" | cut -d'|' -f2)

    # Se length é similar ao random (±10%), é falso positivo
    if [[ -n "$random_length" && -n "$real_length" && "$random_length" -gt 0 ]]; then
        local diff=$((real_length - random_length))
        [[ $diff -lt 0 ]] && diff=$((diff * -1))
        local threshold=$((random_length / 10))
        if [[ $diff -lt $threshold ]]; then
            echo "FP"
            return 1
        fi
    fi

    echo "OK|$real_status|$real_length"
    return 0
}

# Filtrar resultados de um scan
filter_results() {
    local json_file="$1"
    local output_file="${json_file%.json}_filtered.json"

    log_info "Filtrando falsos positivos de $(basename "$json_file")..."

    _FF_JSON="$json_file" _FF_OUT="$output_file" python3 << 'PYEOF'
import json
import re
import sys
import os

fp_patterns = [
    r'^\.[a-z]+\.txt$',
    r'^\.[a-z]+$',
    r'^\.ht',
    r'favicon',
    r'robots\.txt',
]

json_file = os.environ.get('_FF_JSON', '')
output_file = os.environ.get('_FF_OUT', '')
if not json_file or not output_file:
    sys.exit(1)

try:
    with open(json_file) as f:
        data = json.load(f)
except Exception:
    sys.exit(1)

results = data.get('results', [])
filtered = []
removed = []

# --- Cluster-based catch-all detection ---
# Group results into size clusters (±5% or ±50 bytes tolerance)
def cluster_values(items, key, pct=5, abs_tol=50):
    """Cluster items by a numeric key with tolerance. Returns list of clusters."""
    sorted_items = sorted(items, key=lambda r: r.get(key, 0))
    clusters = []
    current = []
    for r in sorted_items:
        val = r.get(key, 0)
        if not current:
            current.append(r)
        else:
            anchor = current[0].get(key, 0)
            tol = max(anchor * pct / 100, abs_tol)
            if abs(val - anchor) <= tol:
                current.append(r)
            else:
                clusters.append(current)
                current = [r]
    if current:
        clusters.append(current)
    return clusters

# Size-based clustering
size_clusters = cluster_values(results, 'length', pct=5, abs_tol=50)
catchall_cluster_indices = set()
for cluster in size_clusters:
    if len(cluster) > 10:
        for r in cluster:
            catchall_cluster_indices.add(id(r))

# Word-count clustering as secondary signal
word_clusters = cluster_values(results, 'words', pct=5, abs_tol=10)
for cluster in word_clusters:
    if len(cluster) > 10:
        for r in cluster:
            catchall_cluster_indices.add(id(r))

for r in results:
    url = r.get('url', '')
    path = url.split('/')[-1] if '/' in url else url
    length = r.get('length', 0)

    is_fp = False
    reason = ''

    # Check known FP patterns
    for pattern in fp_patterns:
        if re.search(pattern, path, re.I):
            is_fp = True
            reason = f'pattern: {pattern}'
            break

    # Check catch-all cluster (size or word-count)
    if not is_fp and id(r) in catchall_cluster_indices:
        is_fp = True
        words = r.get('words', '?')
        reason = f'catch-all cluster: size={length}, words={words}'

    if is_fp:
        removed.append({'url': url, 'reason': reason})
    else:
        filtered.append(r)

data['results'] = filtered
data['filtered_count'] = len(removed)
data['removed'] = removed[:20]  # Keep first 20 for reference

with open(output_file, 'w') as f:
    json.dump(data, f, indent=2)

print(f"Original: {len(results)} | Filtrado: {len(filtered)} | Removidos: {len(removed)}")
PYEOF
}

# ============================================================================
# BYPASS 403 - Testar técnicas de bypass
# ============================================================================

bypass_403() {
    local url="$1"

    if [[ -z "$url" ]]; then
        echo "Uso: bypass_403 <url>"
        echo "Exemplo: bypass_403 https://target.com/admin"
        return 1
    fi

    log_phase "BYPASS 403 - $url"

    local base_url="${url%/}"
    local host=$(echo "$url" | sed -E 's#^https?://([^/]+).*#\1#')
    local path=$(echo "$url" | sed -E 's#^https?://[^/]+##')
    [[ -z "$path" ]] && path="/"

    declare -A techniques=(
        # Header bypasses
        ["X-Original-URL"]="X-Original-URL: $path"
        ["X-Rewrite-URL"]="X-Rewrite-URL: $path"
        ["X-Forwarded-For-127"]="X-Forwarded-For: 127.0.0.1"
        ["X-Forwarded-For-localhost"]="X-Forwarded-For: localhost"
        ["X-Forwarded-Host"]="X-Forwarded-Host: localhost"
        ["X-Host"]="X-Host: localhost"
        ["X-Custom-IP-Auth"]="X-Custom-IP-Authorization: 127.0.0.1"
        ["X-Real-IP"]="X-Real-IP: 127.0.0.1"
        ["X-Remote-IP"]="X-Remote-IP: 127.0.0.1"
        ["X-Client-IP"]="X-Client-IP: 127.0.0.1"
        ["X-Remote-Addr"]="X-Remote-Addr: 127.0.0.1"
        ["True-Client-IP"]="True-Client-IP: 127.0.0.1"
        ["Cluster-Client-IP"]="Cluster-Client-IP: 127.0.0.1"
        ["X-ProxyUser-Ip"]="X-ProxyUser-Ip: 127.0.0.1"
        ["Client-IP"]="Client-IP: 127.0.0.1"
        ["Forwarded"]="Forwarded: for=127.0.0.1"
    )

    # Path bypasses
    declare -a path_bypasses=(
        "${path}/"
        "${path}/."
        "//${path}"
        "${path}..;/"
        "${path};/"
        "${path}%20"
        "${path}%09"
        "${path}?"
        "${path}#"
        "${path}/*"
        "${path}.html"
        "${path}.php"
        "${path}.json"
        "/${path}"
        "${path}/.randomfile"
        ".${path}"
        "${path}..%00"
        "${path}..%0d"
        "${path}..%0a"
        "${path}..%00/"
    )

    echo ""
    log_info "Testando URL base..."
    local base_response=$(curl -s -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "$url" --max-time 5)
    echo -e "  Base: ${YELLOW}$base_response${NC}"
    echo ""

    # Testar headers
    log_info "Testando bypass por headers..."
    local found_bypass=false

    for name in "${!techniques[@]}"; do
        local header="${techniques[$name]}"
        local response=$(curl -s -o /dev/null -w "%{http_code}" \
            -H "User-Agent: Mozilla/5.0" \
            -H "$header" \
            "$url" --max-time 5 2>/dev/null)

        if [[ "$response" != "$base_response" && "$response" =~ ^(200|301|302|307)$ ]]; then
            echo -e "  ${GREEN}[✓] $name → $response${NC} (Header: $header)"
            found_bypass=true
        fi
    done

    echo ""
    log_info "Testando bypass por path manipulation..."

    local proto=$(echo "$url" | grep -oP '^https?')
    for bypass_path in "${path_bypasses[@]}"; do
        local test_url="${proto}://${host}${bypass_path}"
        local response=$(curl -s -o /dev/null -w "%{http_code}" \
            -H "User-Agent: Mozilla/5.0" \
            "$test_url" --max-time 5 2>/dev/null)

        if [[ "$response" != "$base_response" && "$response" != "404" && "$response" =~ ^(200|301|302|307)$ ]]; then
            echo -e "  ${GREEN}[✓] Path: $bypass_path → $response${NC}"
            found_bypass=true
        fi
    done

    # HTTP Method bypass
    echo ""
    log_info "Testando bypass por método HTTP..."
    for method in GET POST PUT PATCH DELETE HEAD OPTIONS TRACE CONNECT; do
        local response=$(curl -s -o /dev/null -w "%{http_code}" \
            -X "$method" \
            -H "User-Agent: Mozilla/5.0" \
            "$url" --max-time 5 2>/dev/null)

        if [[ "$response" != "$base_response" && "$response" =~ ^(200|201|204|301|302|307)$ ]]; then
            echo -e "  ${GREEN}[✓] Method: $method → $response${NC}"
            found_bypass=true
        fi
    done

    echo ""
    if $found_bypass; then
        log_success "Bypass(es) encontrado(s)!"
    else
        log_warning "Nenhum bypass encontrado."
    fi
}

# ============================================================================
# ENUMERAÇÃO DE API
# ============================================================================

enum_api() {
    local base_url="$1"
    local wordlist="$2"

    if [[ -z "$base_url" ]]; then
        echo "Uso: enum_api <url_base_api> [wordlist]"
        echo "Exemplo: enum_api https://target.com/api"
        return 1
    fi

    # Wordlist padrão para APIs
    local api_wordlist="${WORDLISTS_DIR}/api-endpoints.txt"
    if [[ -n "$wordlist" && -f "$wordlist" ]]; then
        api_wordlist="$wordlist"
    elif [[ ! -f "$api_wordlist" ]]; then
        # Criar wordlist básica de API
        log_info "Criando wordlist de API..."
        cat > "$api_wordlist" << 'APIWORDS'
v1
v2
v3
api
users
user
admin
auth
login
logout
register
token
refresh
me
profile
account
accounts
settings
config
configuration
health
status
info
version
docs
documentation
swagger
swagger.json
swagger.yaml
openapi
openapi.json
graphql
graphiql
query
mutation
schema
introspection
debug
test
ping
echo
search
upload
download
file
files
image
images
data
export
import
backup
logs
metrics
stats
analytics
dashboard
reports
notifications
messages
comments
posts
items
products
orders
payments
subscriptions
webhooks
callbacks
events
keys
secrets
credentials
tokens
sessions
APIWORDS
    fi

    log_phase "ENUMERAÇÃO DE API - $base_url"

    local output_dir="${RESULTS_DIR}/api_enum_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$output_dir"

    # Testar endpoint base
    log_info "Verificando endpoint base..."
    local base_check=$(curl -s -w "\n%{http_code}" -H "User-Agent: Mozilla/5.0" \
        -H "Accept: application/json" "$base_url" --max-time 10 2>/dev/null)
    local base_body=$(echo "$base_check" | head -n -1)
    local base_status=$(echo "$base_check" | tail -1)

    echo -e "  Status: ${YELLOW}$base_status${NC}"
    if echo "$base_body" | python3 -m json.tool &>/dev/null; then
        echo -e "  ${GREEN}Resposta JSON válida${NC}"
        echo "$base_body" | python3 -m json.tool 2>/dev/null | head -20
    fi

    echo ""
    log_info "Fuzzing endpoints de API..."

    # Calibrar target para detectar catch-all
    local calibration_flags
    calibration_flags=$(calibrate_target "$base_url" 3)
    [[ -n "$calibration_flags" ]] && log_warning "Catch-all detectado → filtro: ${calibration_flags}"

    # FFUF com configurações para API
    ffuf -c \
        -u "${base_url}/FUZZ" \
        -w "$api_wordlist" \
        -H "User-Agent: Mozilla/5.0" \
        -H "Accept: application/json, text/plain, */*" \
        -H "Content-Type: application/json" \
        -t 10 \
        -rate 20 \
        -timeout 10 \
        -mc 200,201,204,301,302,307,400,401,403,405,500 \
        -fc 404 \
        -ac \
        $calibration_flags \
        -o "${output_dir}/api_fuzz.json" \
        -of json

    # Filtrar falsos positivos antes de testar métodos
    if [[ -f "${output_dir}/api_fuzz.json" ]]; then
        local raw_api_count=$(python3 -c "import json; print(len(json.load(open('${output_dir}/api_fuzz.json')).get('results', [])))" 2>/dev/null || echo "0")
        if [[ "$raw_api_count" -gt 0 ]]; then
            filter_results "${output_dir}/api_fuzz.json" 2>&1 | while read -r line; do log_info "$line"; done
            local filtered_api="${output_dir}/api_fuzz_filtered.json"
            if [[ -f "$filtered_api" ]]; then
                cp "$filtered_api" "${output_dir}/api_fuzz.json"
                rm -f "$filtered_api"
            fi
        fi
    fi

    # Testar métodos em endpoints encontrados
    echo ""
    log_info "Testando métodos HTTP em endpoints encontrados..."

    if [[ -f "${output_dir}/api_fuzz.json" ]]; then
        python3 << PYEOF
import json
import subprocess

with open('${output_dir}/api_fuzz.json') as f:
    data = json.load(f)

for r in data.get('results', [])[:10]:
    url = r.get('url', '')
    print(f"\n  Endpoint: {url}")
    for method in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
        try:
            result = subprocess.run([
                'curl', '-s', '-o', '/dev/null', '-w', '%{http_code}',
                '-X', method,
                '-H', 'Content-Type: application/json',
                '-H', 'User-Agent: Mozilla/5.0',
                '--max-time', '5',
                url
            ], capture_output=True, text=True, timeout=10)
            status = result.stdout.strip()
            if status not in ['404', '405']:
                color = '\033[0;32m' if status.startswith('2') else '\033[0;33m'
                print(f"    {color}{method}: {status}\033[0m")
        except:
            pass
PYEOF
    fi

    log_success "Resultados salvos em: ${output_dir}"
}

# ============================================================================
# VERIFICAR INFO DISCLOSURE
# ============================================================================

check_disclosure() {
    local url="$1"

    if [[ -z "$url" ]]; then
        echo "Uso: check_disclosure <url ou dominio>"
        echo "Exemplo: check_disclosure https://target.com"
        return 1
    fi

    # Adicionar protocolo se não tiver
    [[ "$url" != http* ]] && url="https://$url"
    url="${url%/}"

    log_phase "INFO DISCLOSURE CHECK - $url"

    # Arquivos sensíveis comuns
    declare -a sensitive_files=(
        ".git/HEAD"
        ".git/config"
        ".gitignore"
        ".env"
        ".env.local"
        ".env.production"
        ".env.backup"
        "config.php"
        "config.php.bak"
        "config.inc.php"
        "configuration.php"
        "settings.php"
        "database.yml"
        "database.php"
        "db.php"
        "wp-config.php"
        "wp-config.php.bak"
        "web.config"
        "phpinfo.php"
        "info.php"
        "test.php"
        ".htaccess"
        ".htpasswd"
        "server-status"
        "server-info"
        ".DS_Store"
        "Thumbs.db"
        "crossdomain.xml"
        "clientaccesspolicy.xml"
        "robots.txt"
        "sitemap.xml"
        "security.txt"
        ".well-known/security.txt"
        "composer.json"
        "composer.lock"
        "package.json"
        "package-lock.json"
        "yarn.lock"
        "Gemfile"
        "Gemfile.lock"
        "requirements.txt"
        "Pipfile"
        "Pipfile.lock"
        ".svn/entries"
        ".svn/wc.db"
        "backup.sql"
        "backup.zip"
        "backup.tar.gz"
        "dump.sql"
        "database.sql"
        "db.sql"
        ".bash_history"
        ".ssh/id_rsa"
        "id_rsa"
        "id_dsa"
        "credentials.json"
        "credentials.xml"
        "secrets.json"
        "secrets.yml"
        "private.key"
        "server.key"
        "error.log"
        "error_log"
        "debug.log"
        "access.log"
        "access_log"
        "app.log"
        "application.log"
        "Dockerfile"
        "docker-compose.yml"
        ".dockerignore"
        "Jenkinsfile"
        ".travis.yml"
        "bitbucket-pipelines.yml"
        "swagger.json"
        "swagger.yaml"
        "openapi.json"
        "openapi.yaml"
        "api-docs"
        "graphql"
        "actuator/health"
        "actuator/env"
        "actuator/mappings"
        "actuator/configprops"
        "trace"
        "metrics"
        "heapdump"
        "threaddump"
    )

    local output_file="${RESULTS_DIR}/disclosure_$(echo "$url" | sed 's#https\?://##; s#[/:]#_#g')_$(date +%Y%m%d_%H%M%S).txt"
    local found_count=0

    echo "URL Base: $url" > "$output_file"
    echo "Data: $(date)" >> "$output_file"
    echo "========================================" >> "$output_file"
    echo "" >> "$output_file"

    log_info "Verificando ${#sensitive_files[@]} arquivos sensíveis..."
    echo ""

    for file in "${sensitive_files[@]}"; do
        local test_url="${url}/${file}"
        local response=$(curl -s -w "\n%{http_code}|%{size_download}" \
            -H "User-Agent: Mozilla/5.0" \
            --max-time 5 "$test_url" 2>/dev/null)

        local body=$(echo "$response" | head -n -1)
        local meta=$(echo "$response" | tail -1)
        local status=$(echo "$meta" | cut -d'|' -f1)
        local size=$(echo "$meta" | cut -d'|' -f2)

        # Verificar se é resposta real (não erro genérico)
        if [[ "$status" == "200" && "$size" -gt 0 ]]; then
            # Verificar se não é página de erro/404 soft
            if ! echo "$body" | grep -qi "not found\|404\|error\|page doesn't exist"; then
                ((found_count++))
                echo -e "${GREEN}[✓] FOUND:${NC} ${file} (${size} bytes)"

                echo "=== $file ===" >> "$output_file"
                echo "Status: $status | Size: $size bytes" >> "$output_file"
                echo "URL: $test_url" >> "$output_file"
                echo "Content (first 500 chars):" >> "$output_file"
                echo "$body" | head -c 500 >> "$output_file"
                echo -e "\n\n" >> "$output_file"

                # Mostrar preview para arquivos críticos
                if [[ "$file" =~ \.(env|config|key|json|yml|yaml|sql)$ ]] || [[ "$file" =~ ^\.git ]]; then
                    echo -e "${YELLOW}  Preview:${NC}"
                    echo "$body" | head -5 | sed 's/^/    /'
                fi
            fi
        elif [[ "$status" == "403" ]]; then
            # 403 pode indicar que o arquivo existe
            echo -e "${YELLOW}[!] PROTECTED:${NC} ${file} (403 Forbidden)"
        fi
    done

    echo ""
    if [[ $found_count -gt 0 ]]; then
        log_success "$found_count arquivo(s) sensível(is) encontrado(s)!"
        log_info "Relatório salvo em: $output_file"
    else
        log_warning "Nenhum arquivo sensível acessível encontrado."
    fi

    return 0
}

# ============================================================================
# MENU DE AJUDA
# ============================================================================

show_help() {
    draw_line "top"
    box_center "${BOLD}FFUF MASTER - Bug Bounty Edition v${SCRIPT_VERSION}${NC}"
    box_center "${RED}@${GREEN}ofj${YELLOW}aaah${NC}"
    draw_line "mid"
    box_empty
    box_left "${BOLD}${YELLOW}MODOS DE EXECUÇÃO:${NC}"
    box_empty
    box_left "${GREEN}1. SITE ÚNICO (padrão)${NC} - Scan direto em uma URL"
    box_left "   ./ffuf_master.sh <url> [wordlist] [threads] [rate] [mode]"
    box_empty
    box_left "${GREEN}2. FULL RECON (--domains)${NC} - Coleta subdomínios + scan em todos"
    box_left "   ./ffuf_master.sh --domains <dominio> [wordlist] [threads] [rate] [mode]"
    box_empty
    box_left "${RED}3. HUNT MODE (--hunt)${NC} - 200 OK + No WAF → Deep Scan"
    box_left "   ./ffuf_master.sh --hunt <dominio> [wordlist] [threads] [rate]"
    box_left "   ${CYAN}Fluxo: subdomain enum → httpx → triage (200+WAF) → deep scan${NC}"
    box_empty
    box_left "${RED}4. HUNT LIST (--hunt-list)${NC} - Import lista → Permuta → Fuzz"
    box_left "   ./ffuf_master.sh --hunt-list <arquivo_ou_url> [wordlist] [threads] [rate]"
    box_left "   ${CYAN}Fluxo: import → permutação → DNS → httpx → triage → deep scan${NC}"
    box_empty
    box_left "${MAGENTA}5. LOOT MODE (--loot)${NC} - Deep scan: crawl + fuzz + files + dirlist"
    box_left "   ./ffuf_master.sh --loot <hunt_dir|targets_file|url> [wordlist] [threads] [rate]"
    box_left "   ${CYAN}Fluxo: crawl (katana+gospider+gau) → sensitive fuzz → file hunt → dirlist → report${NC}"
    box_empty
    draw_line "sep"
    box_left "${BOLD}${YELLOW}EXEMPLOS - SITE ÚNICO:${NC}"
    box_empty
    box_left "  ./ffuf_master.sh https://target.com"
    box_left "  ./ffuf_master.sh https://api.target.com/v1"
    box_left "  ./ffuf_master.sh target.com auto 40 100"
    box_left "  ./ffuf_master.sh target.com auto 5 10 stealth"
    box_empty
    draw_line "sep"
    box_left "${BOLD}${YELLOW}EXEMPLOS - FULL RECON (--domains):${NC}"
    box_empty
    box_left "  ./ffuf_master.sh --domains target.com"
    box_left "  ./ffuf_master.sh -d target.com auto 40 100"
    box_left "  ./ffuf_master.sh --domains target.com auto 5 10 stealth"
    box_empty
    box_left "${CYAN}FLUXO DO --domains:${NC}"
    box_left "  subfinder + tldfinder → permutação → puredns → httpx → ffuf"
    box_empty
    draw_line "sep"
    box_left "${BOLD}${YELLOW}EXEMPLOS - HUNT LIST (--hunt-list):${NC}"
    box_empty
    box_left "  ${CYAN}# Direto de uma URL (GitHub Gist, raw paste, etc.):${NC}"
    box_left "  ./ffuf_master.sh --hunt-list ${GREEN}https://gist.githubusercontent.com/\\${NC}"
    box_left "    ${GREEN}RedBullSecurity/.../redbull-scope.txt${NC}"
    box_empty
    box_left "  ${CYAN}# Arquivo local com lista de domínios:${NC}"
    box_left "  ./ffuf_master.sh --hunt-list ${GREEN}domains.txt${NC}"
    box_empty
    box_left "  ${CYAN}# Com modo stealth (WAF-safe):${NC}"
    box_left "  ./ffuf_master.sh --hunt-list ${GREEN}domains.txt${NC} auto 5 10 stealth"
    box_empty
    box_left "  ${CYAN}# Pipeline completo (hunt → loot):${NC}"
    box_left "  ./ffuf_master.sh --hunt-list ${GREEN}domains.txt${NC}"
    box_left "  ./ffuf_master.sh --loot ${GREEN}~/ffuf_scans/results/hunt_list_*/\${NC}"
    box_empty
    box_left "${CYAN}FLUXO DO --hunt-list:${NC}"
    box_left "  import → permutação → DNS → httpx → ${RED}cdncheck${NC} → ffuf"
    box_left "  ${YELLOW}(hosts com CDN/WAF são excluídos automaticamente)${NC}"
    box_empty
    draw_line "sep"
    box_left "${BOLD}${YELLOW}MODOS DE VELOCIDADE:${NC}"
    box_empty
    box_left "  ${GREEN}normal${NC}      30 threads, 50 req/s (padrão, balanceado)"
    box_left "  ${YELLOW}stealth${NC}     5 threads, 10 req/s (lento, para WAFs agressivos)"
    box_left "  ${RED}aggressive${NC}  50 threads, 150 req/s (rápido, pode causar bloqueio)"
    box_empty
    draw_line "sep"
    box_left "${BOLD}${YELLOW}WORDLIST INTELIGENTE:${NC}"
    box_empty
    box_left "  O ffuf seleciona automaticamente a wordlist baseado no contexto:"
    box_empty
    box_left "  • Subdomínios api.*, gateway.*, graphql.* → Wordlist de API"
    box_left "  • Paths /api/*, /v1/*, /graphql/* → Wordlist de API"
    box_left "  • Outros domínios/paths → Wordlist de diretórios"
    box_empty
    draw_line "sep"
    box_left "${BOLD}${YELLOW}FERRAMENTAS AUXILIARES:${NC}"
    box_empty
    box_left "  ${GREEN}bypass${NC} <url>        Testa bypass em 403 (headers, path, methods)"
    box_left "  ${GREEN}api${NC} <url_base>      Enumera endpoints de API"
    box_left "  ${GREEN}disclosure${NC} <url>     Verifica arquivos sensíveis"
    box_left "  ${GREEN}filter${NC} <arq.json>   Filtra falsos positivos"
    box_empty
    draw_line "sep"
    box_left "${BOLD}${YELLOW}SETUP INICIAL:${NC}"
    box_empty
    box_left "  ${GREEN}./ffuf_master.sh --setup${NC}"
    box_left "      ${BOLD}Instala TUDO automaticamente:${NC}"
    box_left "      Go + ffuf + subfinder + httpx + puredns + dnsx"
    box_left "      + katana + gospider + gau + tldfinder + ${CYAN}cdncheck${NC} + wordlists"
    box_empty
    draw_line "sep"
    box_left "${BOLD}${YELLOW}CDN/WAF PROTECTION (cdncheck):${NC}"
    box_empty
    box_left "  Hosts com CDN/WAF são ${RED}automaticamente excluídos${NC} do scan."
    box_left "  • ${YELLOW}WAF${NC} (cloudflare, akamai, incapsula...) → scan cancelado"
    box_left "  • ${BLUE}CDN${NC} (cloudfront, fastly, azureedge...) → scan cancelado"
    box_left "  • ${CYAN}Cloud${NC} (aws, azure, gcp) → rate reduzido"
    box_left "  Powered by: projectdiscovery/cdncheck"
    box_empty
    box_left "  ./ffuf_master.sh --download-wordlists"
    box_left "      Baixa apenas wordlists: DIR + API + DNS (SecLists)"
    box_empty
    draw_line "bot"
}

# ============================================================================
# EXECUÇÃO PRINCIPAL
# ============================================================================

main() {
    # Verificar dependências (exceto para help e download)
    case "${1:-}" in
        --help|-h|help|"")
            ;;
        --download-wordlists|download)
            ;;
        --setup|-S|setup)
            ;;
        *)
            check_dependencies || return 1
            ;;
    esac

    case "${1:-}" in
        --help|-h|help)
            show_help
            ;;
        --setup|-S|setup)
            setup_all
            ;;
        --download-wordlists|download)
            download_wordlists
            ;;
        --domains|-d)
            # Full recon com enumeração de subdomínios
            shift
            full_recon "$@"
            ;;
        --hunt|-H)
            # Hunt mode: 200 OK + No WAF → Deep Scan
            shift
            hunt_recon "$@"
            ;;
        --hunt-list|-HL)
            # Hunt list mode: import list → permutate → resolve → triage → fuzz
            shift
            hunt_list "$@"
            ;;
        --loot|-L)
            # Loot mode: crawl + sensitive fuzz + file hunt + dirlist + report
            shift
            loot_scan "$@"
            ;;
        bypass|403|bypass403)
            shift
            bypass_403 "$@"
            ;;
        api|enum-api|enumapi)
            shift
            enum_api "$@"
            ;;
        disclosure|info|sensitive|check)
            shift
            check_disclosure "$@"
            ;;
        filter)
            shift
            filter_results "$@"
            ;;
        quick)
            shift
            quick_scan "$@"
            ;;
        stealth-scan)
            shift
            stealth_scan "$@"
            ;;
        "")
            show_help
            ;;
        *)
            # Scan em site único (sem enumeração de subdomínios)
            single_site_scan "$@"
            ;;
    esac
}

# Se executado diretamente (não sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
else
    # Se sourced, carregar funções
    log_success "FFUF Master v5.1 carregado!"
    log_info "Funções disponíveis: full_recon, hunt_recon, hunt_list, loot_scan, quick_scan, stealth_scan"
    log_info "Execute 'show_help' para ver comandos"
fi
