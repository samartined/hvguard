# HVGuard - textos del "chrome" (cabecera, pestanas, semaforo). ES.
# Los textos propios de cada modulo viven dentro del modulo. Se carga con lectura UTF-8 explicita
# (Import-HvgStrings) para preservar acentos en Windows PowerShell 5.1 y PowerShell 7.
@{
    AppTitle           = 'HVGuard'
    AppSubtitle        = 'Protege tu equipo de lo que desactiva el crack'
    LangLabel          = 'Idioma'
    Ready              = 'Listo.'
    DetailsHeader      = 'Ver detalles'

    Tabs = @{
        Status  = 'Comprobar'
        Repair  = 'Reparar'
        Harden  = 'Blindar'
        Folder  = 'Carpeta del juego'
        Scanner = 'Escáner'
    }

    Status = @{
        NotChecked  = 'SIN COMPROBAR'
        Working     = 'COMPROBANDO…'
        Protected   = 'PROTEGIDO'
        AtRisk      = 'EN RIESGO'
        Compromised = 'COMPROMETIDO'
        Unknown     = 'NO CONCLUYENTE'
    }

    StatusHintDefault  = 'Pulsa "Comprobar" para revisar el estado de tu equipo.'
    ReadOnlyBanner     = 'Modo solo lectura: HVGuard se está ejecutando sin permisos de administrador. Puedes Comprobar y Analizar, pero para Reparar o Blindar reinícialo como administrador.'
    ReadOnlyTag        = 'solo lectura'
    AdminTag           = 'administrador'
    NeverFalseSecurity = 'El verde significa "no encontré amenazas conocidas", nunca "es seguro".'
    CopyAll            = 'Copiar todo'
    Copied             = 'Copiado al portapapeles.'
}
