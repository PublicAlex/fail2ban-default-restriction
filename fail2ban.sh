#!/bin/bash

# Script completo: Configurar Fail2ban Anti-Bots con bloqueo incremental
echo "🛡️ CONFIGURADOR FAIL2BAN ANTI-BOTS AVANZADO"
echo

set -e

# ========================================
# CONFIGURACIÓN PERSONALIZABLE
# ========================================
MAX_RETRY=5                       # Intentos permitidos antes del ban
BAN_TIME=3600                     # Tiempo inicial de ban (1 hora)
FIND_TIME=3000                     # Ventana de tiempo para contar intentos (30 min)
INCREMENTAL_FACTOR=2              # Factor de multiplicación para ban incremental
MAX_BAN_TIME=604800               # Tiempo máximo de ban (1 semana)
EMAIL_ALERTS=""                   # Email para alertas (opcional, dejar vacío para desactivar)
WHITELIST_IPS="127.0.0.1/8 192.168.0.0/16 10.0.0.0/8 172.16.0.0/12"  # IPs nunca banear

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

show_message() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

show_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

show_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

show_config() {
    echo -e "${BLUE}[CONFIG]${NC} $1"
}

# Verificar root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        show_error "Este script debe ejecutarse como root (usa sudo)"
        exit 1
    fi
}

# Detectar distribución
detect_distro() {
    if [[ -f /etc/debian_version ]]; then
        DISTRO="debian"
        PKG_MANAGER="apt-get"
        SERVICE_MANAGER="systemctl"
    elif [[ -f /etc/redhat-release ]]; then
        DISTRO="rhel"
        PKG_MANAGER="yum"
        SERVICE_MANAGER="systemctl"
    elif [[ -f /etc/arch-release ]]; then
        DISTRO="arch"
        PKG_MANAGER="pacman"
        SERVICE_MANAGER="systemctl"
    else
        show_error "Distribución no soportada"
        exit 1
    fi
    show_message "Distribución detectada: $DISTRO"
}

# Mostrar configuración
show_configuration() {
    echo -e "${PURPLE}=== Configuración Anti-Bots ===${NC}"
    show_config "Intentos máximos: $MAX_RETRY"
    show_config "Tiempo inicial de ban: $BAN_TIME segundos ($(($BAN_TIME/60)) minutos)"
    show_config "Ventana de detección: $FIND_TIME segundos ($(($FIND_TIME/60)) minutos)"
    show_config "Factor incremental: x$INCREMENTAL_FACTOR"
    show_config "Ban máximo: $MAX_BAN_TIME segundos ($(($MAX_BAN_TIME/86400)) días)"
    show_config "IPs en whitelist: $WHITELIST_IPS"
    [[ -n "$EMAIL_ALERTS" ]] && show_config "Alertas por email: $EMAIL_ALERTS" || show_config "Alertas por email: Desactivadas"
    echo
}

# Instalar fail2ban y dependencias
install_fail2ban() {
    show_message "Instalando fail2ban y dependencias..."
    
    case $DISTRO in
        "debian")
            $PKG_MANAGER update
            $PKG_MANAGER install -y fail2ban iptables rsyslog whois
            ;;
        "rhel")
            $PKG_MANAGER install -y epel-release
            $PKG_MANAGER install -y fail2ban iptables rsyslog whois
            ;;
        "arch")
            $PKG_MANAGER -S fail2ban iptables rsyslog whois --noconfirm
            ;;
    esac
    
    # Verificar instalación
    if ! command -v fail2ban-server &> /dev/null; then
        show_error "Error: No se pudo instalar fail2ban"
        exit 1
    fi
    
    show_message "Fail2ban instalado correctamente ✓"
}

# Detectar servicios disponibles
detect_services() {
    show_message "Detectando servicios instalados..."
    
    SERVICES_DETECTED=""
    
    # Detectar logs de SSH
    if [[ -f /var/log/auth.log ]]; then
        SSH_LOG="/var/log/auth.log"
        SERVICES_DETECTED="$SERVICES_DETECTED SSH"
    elif [[ -f /var/log/secure ]]; then
        SSH_LOG="/var/log/secure"
        SERVICES_DETECTED="$SERVICES_DETECTED SSH"
    else
        SSH_LOG="/var/log/messages"
        SERVICES_DETECTED="$SERVICES_DETECTED SSH"
    fi
    
    # Detectar Apache
    if [[ -d /var/log/apache2 ]] || [[ -f /var/log/apache2/error.log ]]; then
        APACHE_LOG="/var/log/apache2/error.log"
        SERVICES_DETECTED="$SERVICES_DETECTED Apache"
    elif [[ -d /var/log/httpd ]] || [[ -f /var/log/httpd/error_log ]]; then
        APACHE_LOG="/var/log/httpd/error_log"
        SERVICES_DETECTED="$SERVICES_DETECTED Apache"
    fi
    
    # Detectar Nginx
    if [[ -f /var/log/nginx/error.log ]]; then
        NGINX_LOG="/var/log/nginx/error.log"
        SERVICES_DETECTED="$SERVICES_DETECTED Nginx"
    fi
    
    # Detectar Postfix
    if [[ -f /var/log/mail.log ]]; then
        MAIL_LOG="/var/log/mail.log"
        SERVICES_DETECTED="$SERVICES_DETECTED Mail"
    elif [[ -f /var/log/maillog ]]; then
        MAIL_LOG="/var/log/maillog"
        SERVICES_DETECTED="$SERVICES_DETECTED Mail"
    fi
    
    show_message "Servicios detectados:$SERVICES_DETECTED"
}

# Configurar fail2ban principal
configure_fail2ban_main() {
    show_message "Configurando fail2ban principal..."
    
    # Backup de configuración original
    [[ -f /etc/fail2ban/jail.conf ]] && cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.conf.backup

    cat > /etc/fail2ban/jail.local << EOF
# Configuración principal de Fail2ban Anti-Bots
[DEFAULT]
# IPs que nunca serán baneadas
ignoreip = $WHITELIST_IPS

# Configuración de tiempo
bantime = $BAN_TIME
findtime = $FIND_TIME
maxretry = $MAX_RETRY

# Configuración incremental
bantime.increment = true
bantime.factor = $INCREMENTAL_FACTOR
bantime.maxtime = $MAX_BAN_TIME

# Backend para monitoreo de logs
backend = auto

# Configuración de email (si está habilitado)
EOF

    # Agregar configuración de email si está definido
    if [[ -n "$EMAIL_ALERTS" ]]; then
        cat >> /etc/fail2ban/jail.local << EOF
destemail = $EMAIL_ALERTS
sendername = Fail2ban-$(hostname)
mta = sendmail
action = %(action_mwl)s
EOF
    else
        cat >> /etc/fail2ban/jail.local << EOF
action = %(action_)s
EOF
    fi

    show_message "Configuración principal creada ✓"
}

# Configurar jail para SSH
configure_ssh_jail() {
    show_message "Configurando protección SSH..."
    
    cat >> /etc/fail2ban/jail.local << EOF

# ===========================================
# PROTECCIÓN SSH ANTI-BOTS
# ===========================================
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = $SSH_LOG
maxretry = $MAX_RETRY
bantime = $BAN_TIME
findtime = $FIND_TIME

EOF

    show_message "Protección SSH configurada ✓"
}

# Configurar jails adicionales para servicios detectados
configure_additional_jails() {
    show_message "Configurando protecciones adicionales..."
    
    cat >> /etc/fail2ban/jail.local << EOF

# ===========================================
# PROTECCIONES ADICIONALES (SOLO SERVICIOS DETECTADOS)
# ===========================================
EOF

    # Solo agregar Apache si fue detectado
    if [[ -n "$APACHE_LOG" ]]; then
        show_message "Configurando protección Apache..."
        cat >> /etc/fail2ban/jail.local << EOF

# Protección Apache
[apache-auth]
enabled = true
port = http,https
filter = apache-auth
logpath = $APACHE_LOG
maxretry = 3
bantime = $BAN_TIME
findtime = $FIND_TIME

[apache-badbots]
enabled = true
port = http,https
filter = apache-badbots
logpath = $APACHE_LOG
maxretry = 2
bantime = $(($BAN_TIME * 2))

EOF
    fi

    # Solo agregar Nginx si fue detectado
    if [[ -n "$NGINX_LOG" ]]; then
        show_message "Configurando protección Nginx..."
        cat >> /etc/fail2ban/jail.local << EOF

# Protección Nginx
[nginx-http-auth]
enabled = true
port = http,https
filter = nginx-http-auth
logpath = $NGINX_LOG
maxretry = 3
bantime = $BAN_TIME
findtime = $FIND_TIME

[nginx-noscript]
enabled = true
port = http,https
filter = nginx-noscript
logpath = $NGINX_LOG
maxretry = 2

EOF
    fi

    # Solo agregar Mail si fue detectado
    if [[ -n "$MAIL_LOG" ]]; then
        show_message "Configurando protección Mail..."
        cat >> /etc/fail2ban/jail.local << EOF

# Protección Postfix
[postfix]
enabled = true
port = smtp,465,submission
filter = postfix
logpath = $MAIL_LOG
maxretry = 3
bantime = $BAN_TIME

EOF
    fi

    show_message "Protecciones adicionales configuradas ✓"
}

# Probar configuración antes de iniciar
test_configuration() {
    show_message "Probando configuración de fail2ban..."
    
    if fail2ban-client --test; then
        show_message "✅ Configuración válida"
        return 0
    else
        show_error "❌ Error en configuración"
        show_warning "Creando configuración mínima de respaldo..."
        
        # Configuración de emergencia solo SSH
        cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
ignoreip = $WHITELIST_IPS
bantime = $BAN_TIME
findtime = $FIND_TIME
maxretry = $MAX_RETRY
bantime.increment = true
bantime.factor = $INCREMENTAL_FACTOR
bantime.maxtime = $MAX_BAN_TIME
backend = auto
action = %(action_)s

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = $SSH_LOG
maxretry = $MAX_RETRY
bantime = $BAN_TIME
findtime = $FIND_TIME
EOF
        
        if fail2ban-client --test; then
            show_message "✅ Configuración mínima válida"
            return 0
        else
            show_error "❌ Error crítico en configuración"
            return 1
        fi
    fi
}

# Configurar iptables para fail2ban
configure_iptables() {
    show_message "Configurando iptables para fail2ban..."
    
    # Asegurar que iptables esté instalado y funcionando
    if command -v iptables &> /dev/null; then
        # Crear cadena personalizada para fail2ban si no existe
        iptables -N fail2ban-ssh 2>/dev/null || true
        iptables -A INPUT -p tcp --dport 22 -j fail2ban-ssh 2>/dev/null || true
        iptables -A fail2ban-ssh -j RETURN 2>/dev/null || true
    fi
    
    show_message "Iptables configurado ✓"
}

# Crear scripts de monitoreo
create_monitoring_scripts() {
    show_message "Creando scripts de monitoreo..."
    
    # Script para ver estadísticas
    cat > /usr/local/bin/fail2ban-stats.sh << 'EOF'
#!/bin/bash
echo "🛡️ === ESTADÍSTICAS FAIL2BAN ==="
echo
echo "📊 Estado de los jails:"
fail2ban-client status

echo
echo "🚫 IPs actualmente baneadas:"
for jail in $(fail2ban-client status | grep "Jail list:" | cut -d: -f2 | tr ',' '\n' | tr -d ' '); do
    if [[ -n "$jail" ]]; then
        banned=$(fail2ban-client status $jail | grep "Currently banned:" | cut -d: -f2 | tr -d ' ')
        if [[ -n "$banned" && "$banned" != "0" ]]; then
            echo "  [$jail]: $banned IPs"
            fail2ban-client status $jail | grep "Banned IP list:" | cut -d: -f2
        fi
    fi
done

echo
echo "📈 Estadísticas detalladas por jail:"
for jail in $(fail2ban-client status | grep "Jail list:" | cut -d: -f2 | tr ',' '\n' | tr -d ' '); do
    if [[ -n "$jail" ]]; then
        echo "--- $jail ---"
        fail2ban-client status $jail
        echo
    fi
done
EOF

    # Script para desbanear IP
    cat > /usr/local/bin/fail2ban-unban.sh << 'EOF'
#!/bin/bash
if [[ $# -ne 1 ]]; then
    echo "Uso: $0 <IP_ADDRESS>"
    echo "Ejemplo: $0 192.168.1.100"
    exit 1
fi

IP=$1
echo "🔓 Desbaneando IP: $IP"

for jail in $(fail2ban-client status | grep "Jail list:" | cut -d: -f2 | tr ',' '\n' | tr -d ' '); do
    if [[ -n "$jail" ]]; then
        fail2ban-client set $jail unbanip $IP 2>/dev/null && echo "  ✅ Desbaneada de $jail" || echo "  ⚠️  No estaba baneada en $jail"
    fi
done

echo "🎯 Proceso completado"
EOF

    # Script para ver logs en tiempo real
    cat > /usr/local/bin/fail2ban-monitor.sh << 'EOF'
#!/bin/bash
echo "🔍 MONITOR FAIL2BAN EN TIEMPO REAL"
echo "Presiona Ctrl+C para salir"
echo "================================"
tail -f /var/log/fail2ban.log | grep --line-buffered -E "(Ban|Unban|Found|ERROR|WARNING)" | while read line; do
    if echo "$line" | grep -q "Ban"; then
        echo -e "\033[0;31m[BAN]   $line\033[0m"
    elif echo "$line" | grep -q "Unban"; then
        echo -e "\033[0;32m[UNBAN] $line\033[0m"
    elif echo "$line" | grep -q "Found"; then
        echo -e "\033[0;33m[FOUND] $line\033[0m"
    elif echo "$line" | grep -q "ERROR"; then
        echo -e "\033[1;31m[ERROR] $line\033[0m"
    elif echo "$line" | grep -q "WARNING"; then
        echo -e "\033[1;33m[WARN]  $line\033[0m"
    else
        echo "$line"
    fi
done
EOF

    chmod +x /usr/local/bin/fail2ban-*.sh
    show_message "Scripts de monitoreo creados ✓"
}

# Iniciar y habilitar servicios
start_services() {
    show_message "Iniciando servicios..."
    
    # Habilitar e iniciar rsyslog
    $SERVICE_MANAGER enable rsyslog
    $SERVICE_MANAGER restart rsyslog
    
    # Verificar que la configuración es válida antes de iniciar
    if ! test_configuration; then
        show_error "No se puede iniciar fail2ban con configuración inválida"
        exit 1
    fi
    
    # Habilitar e iniciar fail2ban
    $SERVICE_MANAGER enable fail2ban
    $SERVICE_MANAGER restart fail2ban
    
    # Verificar estado
    sleep 3
    if $SERVICE_MANAGER is-active --quiet fail2ban; then
        show_message "Fail2ban iniciado correctamente ✅"
        show_message "Jails activos:"
        fail2ban-client status
    else
        show_error "Error al iniciar fail2ban ❌"
        $SERVICE_MANAGER status fail2ban
        exit 1
    fi
}

# Crear script de prueba
create_test_script() {
    show_message "Creando script de prueba..."
    
    cat > /usr/local/bin/test-fail2ban.sh << EOF
#!/bin/bash

echo "🧪 PROBANDO CONFIGURACIÓN FAIL2BAN"
echo

# Verificar estado del servicio
echo "📊 Estado del servicio:"
systemctl status fail2ban --no-pager -l

echo
echo "🛡️ Jails activos:"
fail2ban-client status

echo
echo "⚙️ Configuración SSH jail:"
fail2ban-client status sshd 2>/dev/null || fail2ban-client status ssh 2>/dev/null || echo "❌ SSH jail no encontrado"

echo
echo "📋 Configuración aplicada:"
echo "  - Intentos máximos: $MAX_RETRY"
echo "  - Tiempo inicial ban: $BAN_TIME segundos"
echo "  - Factor incremental: x$INCREMENTAL_FACTOR"
echo "  - Ban máximo: $MAX_BAN_TIME segundos"

echo
echo "🔧 Comandos útiles:"
echo "  fail2ban-stats.sh       - Ver estadísticas completas"
echo "  fail2ban-monitor.sh     - Monitor en tiempo real"
echo "  fail2ban-unban.sh <IP>  - Desbanear IP específica"

echo
echo "🎯 ¡Configuración lista para proteger contra bots!"
EOF

    chmod +x /usr/local/bin/test-fail2ban.sh
    show_message "Script de prueba creado ✓"
}

# Mostrar resumen final
show_summary() {
    echo
    echo -e "${GREEN}=== 🛡️ FAIL2BAN ANTI-BOTS CONFIGURADO EXITOSAMENTE ===${NC}"
    echo
    echo -e "${BLUE}Configuración aplicada:${NC}"
    echo "  ✅ Intentos permitidos: $MAX_RETRY"
    echo "  ✅ Ban inicial: $BAN_TIME segundos ($(($BAN_TIME/60)) minutos)"
    echo "  ✅ Ban incremental: Factor x$INCREMENTAL_FACTOR"
    echo "  ✅ Ban máximo: $MAX_BAN_TIME segundos ($(($MAX_BAN_TIME/86400)) días)"
    echo "  ✅ Servicios protegidos:$SERVICES_DETECTED"
    echo "  ✅ SSH log: $SSH_LOG"
    [[ -n "$APACHE_LOG" ]] && echo "  ✅ Apache log: $APACHE_LOG"
    [[ -n "$NGINX_LOG" ]] && echo "  ✅ Nginx log: $NGINX_LOG"
    [[ -n "$MAIL_LOG" ]] && echo "  ✅ Mail log: $MAIL_LOG"
    echo
    echo -e "${BLUE}Comandos útiles:${NC}"
    echo "  # Probar configuración:"
    echo "  sudo /usr/local/bin/test-fail2ban.sh"
    echo
    echo "  # Ver estadísticas:"
    echo "  sudo /usr/local/bin/fail2ban-stats.sh"
    echo
    echo "  # Monitor en tiempo real:"
    echo "  sudo /usr/local/bin/fail2ban-monitor.sh"
    echo
    echo "  # Desbanear IP:"
    echo "  sudo /usr/local/bin/fail2ban-unban.sh 192.168.1.100"
    echo
    echo "  # Ver jails activos:"
    echo "  sudo fail2ban-client status"
    echo
    echo -e "${YELLOW}🎯 ¡Tus servidores ahora están protegidos contra bots! 🤖🚫${NC}"
    echo -e "${PURPLE}Los atacantes serán baneados con tiempo incremental: 1h → 2h → 4h → hasta 7 días${NC}"
}

# Función principal
main() {
    check_root
    detect_distro
    show_configuration
    
    echo
    show_message "Iniciando configuración anti-bots..."
    
    install_fail2ban
    detect_services
    configure_fail2ban_main
    configure_ssh_jail
    configure_additional_jails
    configure_iptables
    create_monitoring_scripts
    test_configuration
    start_services
    create_test_script
    
    show_summary
}

# Ejecutar
main "$@"
