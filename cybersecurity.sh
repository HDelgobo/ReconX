#!/bin/bash

# ============================================================
# RECONX v7.4 - OSINT + PENTEST + BANCO DE DADOS
# ============================================================
# Uso: bash reconx.sh
# ============================================================

VERSAO="RECONX v7.4"
DATA_ATUAL=$(date '+%d/%m/%Y %H:%M')
ARQUIVO_LOG="$HOME/reconx_db/log.txt"
BD_DIR="$HOME/reconx_db"

# Cores
VERDE="\033[1;32m"
AZUL="\033[1;34m"
AMARELO="\033[1;33m"
VERMELHO="\033[1;31m"
CIANO="\033[1;36m"
RESET="\033[0m"

mkdir -p "$BD_DIR"/{dominio,scan,pessoa,telefone,cpf,email,ip}
touch "$ARQUIVO_LOG"

banner() {
    clear
    echo -e "${VERDE}"
    echo "██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗"
    echo "██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝"
    echo "██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝ "
    echo "██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗ "
    echo "██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗"
    echo "╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝"
    echo -e "${CIANO}═══════════════════════════════════════════════════${RESET}"
    echo -e "${AMARELO}  $VERSAO - OSINT + PENTEST + BANCO DE DADOS${RESET}"
    echo -e "${AZUL}  Plataforma: GNU/Linux | $DATA_ATUAL${RESET}"
    echo -e "${CIANO}═══════════════════════════════════════════════════${RESET}"
    echo ""
}

# ============================================================
# FUNÇÕES AUXILIARES
# ============================================================

salvar_log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$ARQUIVO_LOG"
}

abrir_links() {
    local -n arr=$1
    local total=${#arr[@]}
    read -p "Abrir links? (s/N): " resp
    if [[ "$resp" =~ ^[sSyY] ]]; then
        echo -e "[1-$total] específico | [t] todos | [0] cancelar"
        read -p "Opção: " opt
        if [[ "$opt" == "t" ]]; then
            for url in "${arr[@]}"; do
                xdg-open "$url" 2>/dev/null
                sleep 0.3
            done
        elif [[ "$opt" =~ ^[0-9]+$ ]] && [ "$opt" -ge 1 ] && [ "$opt" -le "$total" ]; then
            xdg-open "${arr[$((opt-1))]}" 2>/dev/null
        fi
    fi
}

# ============================================================
# OPÇÃO 1 - BUSCAR DOMÍNIO
# ============================================================
buscar_dominio() {
    banner
    echo -e "${AZUL}═══ BUSCAR DOMÍNIO ═══${RESET}\n"
    read -p "Digite o domínio (ex: google.com): " dominio
    [ -z "$dominio" ] && return

    echo -e "\n${AMARELO}[*] Coletando informações de: $dominio${RESET}\n"

    echo -e "${VERDE}[1/8] Resolvendo DNS...${RESET}"
    ip=$(dig +short "$dominio" | head -1)
    echo -e "  ${AZUL}IP:${RESET} $ip"

    echo -e "${VERDE}[2/8] Consultando WHOIS...${RESET}"
    whois "$dominio" 2>/dev/null | grep -E "Domain Name|Registry Expiry|Registrar|Name Server" | head -10 | sed 's/^/  /'

    echo -e "${VERDE}[3/8] Registros DNS...${RESET}"
    echo -e "  ${AZUL}A:${RESET} $(dig +short "$dominio" | tr '\n' ' ')"
    echo -e "  ${AZUL}AAAA:${RESET} $(dig +short AAAA "$dominio" | tr '\n' ' ')"
    echo -e "  ${AZUL}MX:${RESET} $(dig +short MX "$dominio" | tr '\n' ' ')"
    echo -e "  ${AZUL}NS:${RESET} $(dig +short NS "$dominio" | tr '\n' ' ')"
    echo -e "  ${AZUL}TXT:${RESET}"
    dig +short TXT "$dominio" | head -5 | sed 's/^/    /'

    echo -e "${VERDE}[4/8] DNSRECON...${RESET}"
    dnsrecon -d "$dominio" -t std 2>/dev/null | grep -E "\[.*\] (NS|MX|SOA|A )" | head -10 | sed 's/^/  /'

    echo -e "${VERDE}[5/8] DMITRY...${RESET}"
    dmitry -winse "$dominio" 2>/dev/null | head -20 | sed 's/^/  /'

    echo -e "${VERDE}[6/8] Subdomínios (crt.sh)...${RESET}"
    subs=$(curl -s "https://crt.sh/?q=%25.$dominio&output=json" 2>/dev/null | jq -r '.[].name_value' 2>/dev/null | sort -u | head -20)
    if [ -n "$subs" ]; then
        echo "$subs" | sed 's/^/  /'
    else
        echo -e "  ${AMARELO}Nenhum subdomínio encontrado${RESET}"
    fi

    echo -e "${VERDE}[7/8] Headers HTTP + WAF...${RESET}"
    curl -sI "https://$dominio" 2>/dev/null | head -20 | sed 's/^/  /'
    wafw00f "https://$dominio" 2>/dev/null | head -5 | sed 's/^/  /'

    arquivo="$BD_DIR/dominio/$dominio.txt"
    {
        echo "=== INFORMAÇÕES DO DOMÍNIO ==="
        echo "Domínio: $dominio"
        echo "IP: $ip"
        echo ""
        echo "=== WHOIS (resumo) ==="
        whois "$dominio" 2>/dev/null | grep -E "Domain Name|Registry Expiry|Registrar|Name Server" | head -10
        echo ""
        echo "=== DNS RECORDS ==="
        echo "A: $(dig +short "$dominio" | tr '\n' ' ')"
        echo "AAAA: $(dig +short AAAA "$dominio" | tr '\n' ' ')"
        echo "MX: $(dig +short MX "$dominio" | tr '\n' ' ')"
        echo "NS: $(dig +short NS "$dominio" | tr '\n' ' ')"
        echo "TXT:"
        dig +short TXT "$dominio"
        echo ""
        echo "=== SUBDOMÍNIOS ==="
        echo "$subs"
        echo ""
        echo "=== HEADERS HTTP ==="
        curl -sI "https://$dominio" 2>/dev/null
        echo ""
        echo "=== GEOLOCALIZAÇÃO ==="
        curl -s "http://ip-api.com/json/$ip" 2>/dev/null | jq -r '"País: \(.country)\nCidade: \(.city)\nProvedor: \(.isp)"' 2>/dev/null
    } > "$arquivo"

    echo -e "\n${VERDE}[✓] Salvo no banco de dados!${RESET}"
    echo -e "  → $arquivo"

    read -p $'\nDeseja salvar relatório TXT extra? (s/N): ' extra
    if [[ "$extra" =~ ^[sS] ]]; then
        cp "$arquivo" "$BD_DIR/dominio/${dominio}_relatorio_$(date +%Y%m%d_%H%M%S).txt"
        echo -e "${VERDE}Relatório extra salvo!${RESET}"
    fi

    salvar_log "Domínio: $dominio ($ip)"
    read -p $'\nPressione ENTER para voltar...'
}

# ============================================================
# OPÇÃO 2 - SCAN NMAP
# ============================================================
scan_nmap() {
    while true; do
        banner
        echo -e "${AZUL}═══ SCAN NMAP - OPÇÕES AVANÇADAS ═══${RESET}"
        echo -e "${AMARELO}⚠  AVISO: Nmap pode demorar. Ctrl+C para cancelar.${RESET}\n"
        read -p "Digite IP ou domínio: " alvo
        [ -z "$alvo" ] && return

        echo ""
        echo "ESCOLHA O TIPO DE SCAN:"
        echo ""
        echo "  [1] Scan Rápido (top 100 portas) - mais rápido"
        echo "  [2] Scan Completo (top 1000 portas) - mais completo"
        echo "  [3] Scan de Serviços (+ versão) - descobre versão dos serviços"
        echo "  [4] Scan SO + Scripts - detecta SO + scripts (requer root p/ SO)"
        echo "  [5] Scan de Rede - só descobre se o host está ativo"
        echo "  [6] Scan Silencioso - lento, tenta não ser detectado (evite em hosts remotos)"
        echo "  [7] Scan UDP - portas UDP (requer root para resultados reais)"
        echo "  [8] Scan + Busca Exploits - procura explorações nos serviços"
        echo "  [9] Scan Completo + Scripts - igual opção 4 (sem Nikto)"
        echo "  [10] Scan Personalizado - você digita os argumentos"
        echo "  [0] Cancelar"
        echo ""

        read -p "Opção: " tipo

        [ "$tipo" == "0" ] && return

        local nmap_cmd=""
        local desc=""

        case $tipo in
            1) nmap_cmd="nmap -sT --top-ports 100 -T4 $alvo" ; desc="Scan Rápido" ;;
            2) nmap_cmd="nmap -sT --top-ports 1000 -T4 $alvo" ; desc="Scan Completo" ;;
            3) nmap_cmd="nmap -sT -sV --top-ports 1000 -T4 $alvo" ; desc="Scan de Serviços" ;;
            4)
                if [ "$(id -u)" -ne 0 ]; then
                    echo -e "\n${AMARELO}⚠  Sem root: pulando detecção de SO. Rodando só serviços + scripts.${RESET}"
                    nmap_cmd="nmap -sT -sV -sC --top-ports 1000 -T4 $alvo"
                    desc="Scan Serviços + Scripts (SO pulado)"
                else
                    nmap_cmd="nmap -sT -sV -O -sC --top-ports 1000 -T4 $alvo"
                    desc="Scan SO + Serviços + Scripts"
                fi
                ;;
            5) nmap_cmd="nmap -sn -T4 $alvo"; desc="Scan de Rede" ;;
            6)
                if [ "$(id -u)" -ne 0 ]; then
                    echo -e "\n${AMARELO}⚠  Sem root: usando scan adaptado lento (--data-length 200, T2, top 100 portas).${RESET}"
                    echo -e "  Em redes lentas ou hosts remotos, pode demorar bastante."
                    nmap_cmd="nmap -sT -sV -T2 --top-ports 100 --max-retries 1 --data-length 200 $alvo"
                    desc="Scan Adaptado (sem root)"
                else
                    nmap_cmd="nmap -sS -sV -T2 --top-ports 100 -f -D RND:10 --data-length 200 $alvo"
                    desc="Scan Silencioso (SYN)"
                fi
                echo -e "${AMARELO}  Escaneando top 100 portas com -T2 para evitar travamentos.${RESET}"
                ;;
            7)
                if [ "$(id -u)" -ne 0 ]; then
                    echo -e "\n${VERMELHO}⚠  Scan UDP normalmente requer root.${RESET}"
                    read -p "Tentar com sudo? (s/N): " try_sudo
                    if [[ "$try_sudo" =~ ^[sS] ]]; then
                        nmap_cmd="sudo nmap -sU --top-ports 100 -T4 $alvo"
                        desc="Scan UDP (sudo)"
                        echo -e "${AMARELO}  Pode pedir sua senha sudo.${RESET}"
                    else
                        echo -e "${AMARELO}  Dica: execute o script como: sudo bash reconx.sh${RESET}"
                        read -p $'\nPressione ENTER para continuar...'
                        continue
                    fi
                else
                    nmap_cmd="nmap -sU --top-ports 100 -T4 $alvo"
                    desc="Scan UDP"
                fi
                ;;
            8)
                if [ "$(id -u)" -ne 0 ]; then
                    echo -e "\n${AMARELO}⚠  Sem root: pulando detecção de SO. Rodando só serviços + scripts.${RESET}"
                    nmap_cmd="nmap -sT -sV -sC --top-ports 1000 -T4 $alvo"
                    desc="Scan + Exploits (SO pulado)"
                else
                    nmap_cmd="nmap -sT -sV -O -sC --top-ports 1000 -T4 $alvo"
                    desc="Scan + Exploits"
                fi
                ;;
            9)
                if [ "$(id -u)" -ne 0 ]; then
                    nmap_cmd="nmap -sT -sV -sC --top-ports 1000 -T4 $alvo"
                    desc="Scan Completo + Scripts"
                else
                    nmap_cmd="nmap -sT -sV -O -sC --top-ports 1000 -T4 $alvo"
                    desc="Scan Completo + Scripts + SO"
                fi
                ;;
            10)
                echo -e "\n${AMARELO}Exemplos de argumentos:${RESET}"
                echo "  -p 22,80,443      → escanear portas específicas"
                echo "  -p 1-1000         → escanear range de portas"
                echo "  -p 80 -sV         → porta 80 com versão"
                echo "  --top-ports 500   → top 500 portas"
                echo "  -Pn               → ignorar ping (host offline)"
                echo "  -sT -sV -O -sC    → TCP + versão + SO + scripts"
                echo ""
                read -p "Digite os argumentos (ex: -p 80,443 -sV): " args
                nmap_cmd="nmap -sT $args $alvo"
                desc="Scan Personalizado: $args"
                ;;
            *) echo -e "${VERMELHO}Opção inválida!${RESET}"; sleep 2; continue ;;
        esac

        echo -e "\n${AMARELO}[*] $desc${RESET}"
        echo -e "${CIANO}[*] Executando: $nmap_cmd${RESET}\n"

        resultado=$(eval "$nmap_cmd" 2>&1)
        echo ""
        echo -e "${CIANO}══════════════════ RESULTADO NMAP ══════════════════${RESET}"
        echo "$resultado"
        echo -e "${CIANO}══════════════════════════════════════════════════════${RESET}"

        timestamp=$(date +%Y%m%d_%H%M%S)
        arquivo="$BD_DIR/scan/${alvo}_${timestamp}.txt"
        echo -e "$resultado" > "$arquivo"
        echo -e "\n${VERDE}[✓] Scan concluído! Salvo em: $arquivo${RESET}"
        salvar_log "Nmap $desc → $alvo"

        read -p $'\nPressione ENTER para voltar...'
        return
    done
}

# ============================================================
# OPÇÃO 3 - BUSCAR PESSOA
# ============================================================
buscar_pessoa() {
    banner
    echo -e "${AZUL}═══ BUSCAR PESSOA ═══${RESET}\n"
    read -p "Digite o nome: " nome
    [ -z "$nome" ] && return

    nome_url=$(echo "$nome" | sed 's/ /+/g')
    nome_fmt=$(echo "$nome" | sed 's/ /_/g')
    echo -e "\n${AMARELO}[*] Buscando: $nome${RESET}\n"

    links=()
    links+=("Facebook|https://www.google.com/search?q=site:facebook.com+%22$nome_url%22")
    links+=("Instagram|https://www.google.com/search?q=site:instagram.com+%22$nome_url%22")
    links+=("LinkedIn|https://www.google.com/search?q=site:linkedin.com+%22$nome_url%22")
    links+=("Twitter/X|https://www.google.com/search?q=site:twitter.com+%22$nome_url%22")
    links+=("YouTube|https://www.google.com/search?q=site:youtube.com+%22$nome_url%22")
    links+=("Reddit|https://www.google.com/search?q=site:reddit.com+%22$nome_url%22")
    links+=("TikTok|https://www.google.com/search?q=site:tiktok.com+%22$nome_url%22")
    links+=("Pinterest|https://www.google.com/search?q=site:pinterest.com+%22$nome_url%22")
    links+=("Arquivos PDF/DOC|https://www.google.com/search?q=%22$nome_url%22+filetype:pdf+OR+filetype:doc+OR+filetype:docx")
    links+=("Busca Geral Google|https://www.google.com/search?q=%22$nome_url%22")
    links+=("Spokeo|https://www.spokeo.com/$nome_url")
    links+=("PeekYou|https://peekyou.com/$nome_url")
    links+=("Pipl|https://pipl.com/search/?q=$nome_url")
    links+=("Whitepages|https://www.whitepages.com/name/$nome_url")
    links+=("BeenVerified|https://www.beenverified.com/people/$nome_url")
    links+=("411|https://www.411.com/name/$nome_url")
    links+=("Radaris|https://radaris.com/ng/search?q=$nome_url")
    links+=("WhatsMyName|https://whatsmyname.app/?q=$nome_fmt")
    links+=("InstantUsername|https://instantusername.com/?q=$nome_fmt")
    links+=("GitHub|https://github.com/search?q=$nome_url")
    links+=("GitLab|https://gitlab.com/search?search=$nome_url")
    links+=("Pastebin|https://www.google.com/search?q=site:pastebin.com+%22$nome_url%22")
    links+=("Jusbrasil (BR)|https://www.jusbrasil.com.br/busca?q=$nome_url")
    links+=("Escavador (BR)|https://www.escavador.com/pessoas?q=$nome_url")
    links+=("PortalTransparencia (BR)|https://portaldatransparencia.gov.br/pessoa-fisica/busca?pessoa=$nome_url")

    echo -e "${VERDE}  ${#links[@]} links gerados${RESET}"

    echo ""
    echo -e "${CIANO}═══════════════════ LINKS ═══════════════════${RESET}"
    for i in "${!links[@]}"; do
        IFS='|' read -r titulo url <<< "${links[$i]}"
        echo -e "${AMARELO}  [$((i+1))]${RESET} $titulo"
        echo -e "      ${AZUL}$url${RESET}"
    done
    echo -e "${CIANO}════════════════════════════════════════════${RESET}"

    arquivo="$BD_DIR/pessoa/$nome_fmt.txt"
    {
        echo "=== BUSCAR PESSOA ==="
        echo "Nome: $nome"
        echo "Data: $(date)"
        echo ""
        echo "=== LINKS ==="
        for i in "${!links[@]}"; do
            IFS='|' read -r titulo url <<< "${links[$i]}"
            echo "[$((i+1))] $titulo: $url"
        done
    } > "$arquivo"
    echo -e "\n${VERDE}[✓] Salvo no banco de dados!${RESET}"
    echo -e "  → $arquivo"

    urls_only=()
    for item in "${links[@]}"; do
        IFS='|' read -r _ url <<< "$item"
        urls_only+=("$url")
    done
    abrir_links urls_only

    salvar_log "Pessoa: $nome (${#links[@]} links)"
    read -p $'\nPressione ENTER para voltar...'
}

# ============================================================
# OPÇÃO 4 - BUSCAR TELEFONE
# ============================================================
buscar_telefone() {
    banner
    echo -e "${AZUL}═══ BUSCAR TELEFONE (MUNDIAL) ═══${RESET}\n"
    echo -e "${AMARELO}Formato: código do país + número (ex: 5511999999999)${RESET}"
    echo -e "${AMARELO}Ou apenas o número (ex: 11999999999) que tentaremos detectar${RESET}"
    read -p "Digite o telefone: " telefone
    [ -z "$telefone" ] && return

    pais=""
    pais_nome=""
    estado=""

    if [[ "$telefone" =~ ^55 ]]; then
        pais="55"
        pais_nome="Brasil"
        ddd="${telefone:2:2}"
        case "$ddd" in
            11|12|13|14|15|16|17|18|19) estado="SP" ;;
            21|22|24) estado="RJ" ;;
            27|28) estado="ES" ;;
            31|32|33|34|35|37|38) estado="MG" ;;
            41|42|43|44|45|46) estado="PR" ;;
            47|48|49) estado="SC" ;;
            51|53|54|55) estado="RS" ;;
            61) estado="DF" ;;
            62|64) estado="GO" ;;
            63) estado="TO" ;;
            65|66) estado="MT" ;;
            67) estado="MS" ;;
            68) estado="AC" ;;
            69) estado="RO" ;;
            71|73|74|75|77) estado="BA" ;;
            79) estado="SE" ;;
            81|87) estado="PE" ;;
            82) estado="AL" ;;
            83) estado="PB" ;;
            84) estado="RN" ;;
            85|88) estado="CE" ;;
            86|89) estado="PI" ;;
            91|93|94) estado="PA" ;;
            92|97) estado="AM" ;;
            95) estado="RR" ;;
            96) estado="AP" ;;
            98|99) estado="MA" ;;
            *) estado="Desconhecido" ;;
        esac
        echo -e "${VERDE}  → País: Brasil (55) | DDD: $ddd | Estado: $estado${RESET}"
    elif [[ "$telefone" =~ ^1 ]]; then
        pais="1"
        pais_nome="EUA/Canadá"
        echo -e "${VERDE}  → País: EUA/Canadá (1)${RESET}"
    elif [[ "$telefone" =~ ^44 ]]; then
        pais="44"
        pais_nome="Reino Unido"
        echo -e "${VERDE}  → País: Reino Unido (44)${RESET}"
    else
        if [[ "$telefone" =~ ^[0-9]{10,11}$ ]]; then
            pais="55"
            pais_nome="Brasil (assumido)"
            ddd="${telefone:0:2}"
            echo -e "${AMARELO}  → Assumindo Brasil (55). DDD: $ddd${RESET}"
            echo -e "  → Para busca completa, use: 55$telefone"
        else
            pais_nome="Desconhecido"
            echo -e "${AMARELO}  → País não detectado. Os links ainda funcionam.${RESET}"
        fi
    fi

    links=()
    links+=("Google|https://www.google.com/search?q=%22$telefone%22+phone")
    links+=("TrueCaller|https://www.truecaller.com/search/$telefone")
    links+=("WhatsApp|https://wa.me/$telefone")

    if [ "$pais" == "1" ]; then
        links+=("Spokeo|https://www.spokeo.com/phone-search?q=$telefone")
        links+=("Whitepages|https://www.whitepages.com/phone/$telefone")
    fi

    if [ "$pais" == "55" ] || [[ "$telefone" =~ ^[0-9]{10,11}$ ]]; then
        links+=("Consulta Telefone Brasil|https://www.consultatelefone.com.br/busca/$telefone")
        links+=("ReclameAqui (telefone)|https://www.reclameaqui.com.br/busca/?q=$telefone")
    fi

    echo ""
    echo -e "${CIANO}═══════════════════ LINKS ═══════════════════${RESET}"
    for i in "${!links[@]}"; do
        IFS='|' read -r titulo url <<< "${links[$i]}"
        echo -e "${AMARELO}  [$((i+1))]${RESET} $titulo"
        echo -e "      ${AZUL}$url${RESET}"
    done
    echo -e "${CIANO}════════════════════════════════════════════${RESET}"

    arquivo="$BD_DIR/telefone/$telefone.txt"
    {
        echo "=== BUSCAR TELEFONE ==="
        echo "Telefone: $telefone"
        echo "País: $pais_nome"
        [ -n "$estado" ] && echo "Estado: $estado"
        echo "Data: $(date)"
        echo ""
        echo "=== LINKS ==="
        for i in "${!links[@]}"; do
            IFS='|' read -r titulo url <<< "${links[$i]}"
            echo "[$((i+1))] $titulo: $url"
        done
    } > "$arquivo"
    echo -e "\n${VERDE}[✓] Salvo no banco de dados!${RESET}"
    echo -e "  → $arquivo"

    urls_only=()
    for item in "${links[@]}"; do
        IFS='|' read -r _ url <<< "$item"
        urls_only+=("$url")
    done
    abrir_links urls_only

    salvar_log "Telefone: $telefone (País: $pais_nome)"
    read -p $'\nPressione ENTER para voltar...'
}

# ============================================================
# OPÇÃO 5 - BUSCAR CPF
# ============================================================
buscar_cpf() {
    banner
    echo -e "${AZUL}═══ BUSCAR CPF ═══${RESET}\n"
    read -p "Digite o CPF (11 números): " cpf
    [ -z "$cpf" ] && return

    cpf=$(echo "$cpf" | sed 's/[^0-9]//g')
    if [ ${#cpf} -ne 11 ]; then
        echo -e "${VERMELHO}CPF inválido! Digite exatamente 11 números.${RESET}"
        read -p "Pressione ENTER para voltar..."
        return
    fi

    cpf_fmt="${cpf:0:3}.${cpf:3:3}.${cpf:6:3}-${cpf:9:2}"

    links=()
    links+=("Jusbrasil|https://www.jusbrasil.com.br/busca?q=$cpf")
    links+=("Escavador|https://www.escavador.com/pessoas?q=$cpf")
    links+=("PortalTransparencia|https://portaldatransparencia.gov.br/pessoa-fisica/busca?pessoa=$cpf")

    echo -e "${AMARELO}⚠  Dados de CPF são protegidos por lei.${RESET}"
    echo -e "${AMARELO}⚠  Os links abaixo podem ou não encontrar resultados.${RESET}\n"

    echo -e "${CIANO}═══════════════════ LINKS ═══════════════════${RESET}"
    for i in "${!links[@]}"; do
        IFS='|' read -r titulo url <<< "${links[$i]}"
        echo -e "${AMARELO}  [$((i+1))]${RESET} $titulo"
        echo -e "      ${AZUL}$url${RESET}"
    done
    echo -e "${CIANO}════════════════════════════════════════════${RESET}"

    arquivo="$BD_DIR/cpf/$cpf.txt"
    {
        echo "=== BUSCAR CPF ==="
        echo "CPF: $cpf_fmt"
        echo "Data: $(date)"
        echo ""
        echo "=== LINKS ==="
        for i in "${!links[@]}"; do
            IFS='|' read -r titulo url <<< "${links[$i]}"
            echo "[$((i+1))] $titulo: $url"
        done
    } > "$arquivo"
    echo -e "\n${VERDE}[✓] Salvo no banco de dados!${RESET}"
    echo -e "  → $arquivo"

    urls_only=()
    for item in "${links[@]}"; do
        IFS='|' read -r _ url <<< "$item"
        urls_only+=("$url")
    done
    abrir_links urls_only

    salvar_log "CPF: $cpf_fmt"
    read -p $'\nPressione ENTER para voltar...'
}

# ============================================================
# OPÇÃO 6 - BUSCAR E-MAIL
# ============================================================
buscar_email() {
    banner
    echo -e "${AZUL}═══ BUSCAR E-MAIL ═══${RESET}\n"
    read -p "Digite o e-mail: " email
    [ -z "$email" ] && return

    dominio_email=$(echo "$email" | cut -d'@' -f2)
    echo -e "\n${AMARELO}[*] Buscando: $email${RESET}\n"

    echo -e "${VERDE}[1/3] Domínio: $dominio_email${RESET}"

    links=()
    links+=("Google|https://www.google.com/search?q=%22$email%22")
    links+=("Pastebin|https://www.google.com/search?q=site:pastebin.com+%22$email%22")
    links+=("GitHub|https://github.com/search?q=%22$email%22")
    links+=("HaveIBeenPwned|https://haveibeenpwned.com/$email")
    links+=("Hunter.io|https://hunter.io/search/$dominio_email")
    links+=("EmailRep|https://emailrep.io/$email")
    links+=("ReclameAqui|https://www.reclameaqui.com.br/busca/?q=$email")
    links+=("Buscapé|https://www.buscape.com.br/busca?q=$email")

    echo -e "${VERDE}[3/3] ${#links[@]} links gerados${RESET}\n"

    echo -e "${CIANO}═══════════════════ LINKS ═══════════════════${RESET}"
    for i in "${!links[@]}"; do
        IFS='|' read -r titulo url <<< "${links[$i]}"
        echo -e "${AMARELO}  [$((i+1))]${RESET} $titulo"
        echo -e "      ${AZUL}$url${RESET}"
    done
    echo -e "${CIANO}════════════════════════════════════════════${RESET}"

    arquivo="$BD_DIR/email/$email.txt"
    {
        echo "=== BUSCAR E-MAIL ==="
        echo "E-mail: $email"
        echo "Domínio: $dominio_email"
        echo "Data: $(date)"
        echo ""
        echo "=== LINKS ==="
        for i in "${!links[@]}"; do
            IFS='|' read -r titulo url <<< "${links[$i]}"
            echo "[$((i+1))] $titulo: $url"
        done
    } > "$arquivo"
    echo -e "\n${VERDE}[✓] Salvo no banco de dados!${RESET}"
    echo -e "  → $arquivo"

    urls_only=()
    for item in "${links[@]}"; do
        IFS='|' read -r _ url <<< "$item"
        urls_only+=("$url")
    done
    abrir_links urls_only

    salvar_log "E-mail: $email"
    read -p $'\nPressione ENTER para voltar...'
}

# ============================================================
# OPÇÃO 7 - MEU IP
# ============================================================
meu_ip() {
    banner
    echo -e "${AZUL}═══ MEU IP PÚBLICO ═══${RESET}\n"

    echo -e "${VERDE}[1/4] IP público...${RESET}"
    ip_pub=$(curl -s ifconfig.me 2>/dev/null)
    echo -e "  IP: ${CIANO}$ip_pub${RESET}"

    echo -e "${VERDE}[2/4] Geolocalização...${RESET}"
    geo=$(curl -s "http://ip-api.com/json/$ip_pub" 2>/dev/null)
    if [ -n "$geo" ]; then
        echo "$geo" | jq -r '"  País: \(.country) | Cidade: \(.city) | ISP: \(.isp)"' 2>/dev/null
        echo "$geo" | jq -r '"  Coordenadas: \(.lat)°, \(.lon)°"' 2>/dev/null
    fi

    echo -e "${VERDE}[3/4] DNS...${RESET}"
    echo -e "  nameserver $(cat /etc/resolv.conf 2>/dev/null | grep nameserver | awk '{print $2}' | head -1)"

    echo -e "${VERDE}[4/4] Rede local...${RESET}"
    ip_local=$(ip -4 addr show 2>/dev/null | grep -oP 'inet \K[\d.]+' | grep -v '127.0.0.1' | head -1)
    if [ -n "$ip_local" ]; then
        echo -e "  IP Local (LAN): ${CIANO}$ip_local${RESET}"
    fi
    gateway=$(ip route 2>/dev/null | grep default | awk '{print $3}' | head -1)
    if [ -n "$gateway" ]; then
        echo -e "  Gateway: ${CIANO}$gateway${RESET}"
    fi
    interface=$(ip route 2>/dev/null | grep default | awk '{print $5}' | head -1)
    if [ -n "$interface" ]; then
        echo -e "  Interface: ${CIANO}$interface${RESET}"
    fi
    mac=$(ip link show "$interface" 2>/dev/null | grep -oP 'link/ether \K[\da-f:]+')
    if [ -n "$mac" ]; then
        echo -e "  MAC: ${CIANO}$mac${RESET}"
    fi

    arquivo="$BD_DIR/ip/$ip_pub.txt"
    {
        echo "=== MEU IP ==="
        echo "IP Público: $ip_pub"
        echo "IP Local: $ip_local"
        echo "Gateway: $gateway"
        echo "Interface: $interface"
        echo "MAC: $mac"
        [ -n "$geo" ] && echo "$geo" | jq '.' 2>/dev/null
        echo ""
        echo "DNS:"
        cat /etc/resolv.conf 2>/dev/null
    } > "$arquivo"
    echo -e "\n${VERDE}[✓] Salvo no banco de dados!${RESET}"
    echo -e "  → $arquivo"

    read -p $'\nAbrir no Google Maps? (s/N): ' maps
    if [[ "$maps" =~ ^[sS] ]]; then
        lat=$(echo "$geo" | jq -r '.lat' 2>/dev/null)
        lon=$(echo "$geo" | jq -r '.lon' 2>/dev/null)
        [ -n "$lat" ] && [ "$lat" != "null" ] && xdg-open "https://www.google.com/maps?q=$lat,$lon" 2>/dev/null
    fi

    salvar_log "Meu IP: $ip_pub | Local: $ip_local"
    read -p $'\nPressione ENTER para voltar...'
}

# ============================================================
# OPÇÃO 8 - CONSULTAR BANCO DE DADOS
# ============================================================
consultar_banco() {
    while true; do
        banner
        echo -e "${AZUL}═══ CONSULTAR BANCO DE DADOS ═══${RESET}\n"

        qtd_d=$(ls "$BD_DIR/dominio/"*.txt 2>/dev/null | wc -l)
        qtd_p=$(ls "$BD_DIR/pessoa/"*.txt 2>/dev/null | wc -l)
        qtd_t=$(ls "$BD_DIR/telefone/"*.txt 2>/dev/null | wc -l)
        qtd_c=$(ls "$BD_DIR/cpf/"*.txt 2>/dev/null | wc -l)
        qtd_e=$(ls "$BD_DIR/email/"*.txt 2>/dev/null | wc -l)
        qtd_i=$(ls "$BD_DIR/ip/"*.txt 2>/dev/null | wc -l)
        total=$((qtd_d + qtd_p + qtd_t + qtd_c + qtd_e + qtd_i))

        echo -e "Categorias:\n"
        echo -e "  ${AZUL}[d] dominio${RESET} ($qtd_d)"
        echo -e "  ${AZUL}[p] pessoa${RESET} ($qtd_p)"
        echo -e "  ${AZUL}[t] telefone${RESET} ($qtd_t)"
        echo -e "  ${AZUL}[c] cpf${RESET} ($qtd_c)"
        echo -e "  ${AZUL}[e] email${RESET} ($qtd_e)"
        echo -e "  ${AZUL}[i] ip${RESET} ($qtd_i)\n"
        echo -e "Total: ${VERDE}$total${RESET} registro(s)\n"

        read -p "Categoria (d/p/t/c/e/i): " cat
        [ -z "$cat" ] && return

        case $cat in
            d) dir="dominio" ;;
            p) dir="pessoa" ;;
            t) dir="telefone" ;;
            c) dir="cpf" ;;
            e) dir="email" ;;
            i) dir="ip" ;;
            *) continue ;;
        esac

        arquivos=("$BD_DIR/$dir/"*.txt)
        if [ ! -e "${arquivos[0]}" ]; then
            echo -e "${AMARELO}Nenhum registro encontrado.${RESET}"
            sleep 2
            continue
        fi

        echo ""
        for i in "${!arquivos[@]}"; do
            nome=$(basename "${arquivos[$i]}")
            echo -e "  ${AMARELO}[$((i+1))]${RESET} $nome"
        done
        echo -e "  ${AMARELO}[0]${RESET} Voltar"
        echo ""

        read -p "Escolha: " esc
        [ "$esc" == "0" ] && continue
        [ "$esc" -gt 0 ] && [ "$esc" -le "${#arquivos[@]}" ] && {
            echo ""
            echo -e "${CIANO}══════════ CONTEÚDO ══════════${RESET}"
            cat "${arquivos[$((esc-1))]}"
            echo ""
            echo -e "${CIANO}══════════════════════════════${RESET}"
            read -p "ENTER para voltar..."
        }
    done
}

# ============================================================
# MAIN
# ============================================================
while true; do
    banner
    echo -e "${VERDE}ESCOLHA UMA OPÇÃO:${RESET}\n"
    echo -e "  ${AZUL}[1]${RESET} Buscar Domínio"
    echo -e "  ${AZUL}[2]${RESET} Scan Nmap"
    echo -e "  ${AZUL}[3]${RESET} Buscar Pessoa"
    echo -e "  ${AZUL}[4]${RESET} Buscar Telefone (Mundial)"
    echo -e "  ${AZUL}[5]${RESET} Buscar CPF"
    echo -e "  ${AZUL}[6]${RESET} Buscar E-mail"
    echo -e "  ${AZUL}[7]${RESET} Meu IP Público"
    echo -e "  ${AZUL}[8]${RESET} Consultar Banco de Dados"
    echo -e "  ${VERMELHO}[0]${RESET} Sair"
    echo ""

    read -p "Opção: " opcao

    case $opcao in
        1) buscar_dominio ;;
        2) scan_nmap ;;
        3) buscar_pessoa ;;
        4) buscar_telefone ;;
        5) buscar_cpf ;;
        6) buscar_email ;;
        7) meu_ip ;;
        8) consultar_banco ;;
        0) echo -e "\n${VERDE}Saindo...${RESET}"; exit 0 ;;
        *) echo -e "${VERMELHO}Opção inválida!${RESET}"; sleep 2 ;;
    esac
done
