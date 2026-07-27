# =====================================================================================================
#  HVGuard - Module M2: Repair (wraps T5 remediation)
#  Pattern: dry-run (without -Apply) -> plain-language preview -> "Apply" (T5 -Apply -Force).
#  Always goes in the direction of hardening (re-enables VBS/HVCI, testsigning off, cleans up IOCs). Handles
#  the "restart/UEFI still pending" case. Respects $Ctx.ReadOnly: without admin, you can preview but not apply.
#  Contract: defines Initialize-HvgModule_M2Repair($Ctx).
# =====================================================================================================

$script:HvgM2 = @{ Panel = $null; Results = $null; BtnScan = $null; BtnApply = $null; S = $null
                   CanApply = $false; Choices = @() }

function Get-HvgM2Strings {
    param([string]$Lang)
    $es = @{
        title    = 'Reparar las protecciones'
        intro    = 'Restaura, en la direccion segura, lo que el crack debilita: reactiva tus protecciones y limpia sus rastros. Primero te muestro que haria SIN cambiar nada, y TU eliges que quieres restaurar, opcion por opcion. Solo cambia algo cuando pulsas "Aplicar lo marcado".'
        btnScan  = 'Ver que haria (sin cambiar nada)'
        btnApply = 'Aplicar cambios'
        scanning = 'Analizando que hay que reparar (T5 en modo simulacion)...'
        applying = 'Aplicando la reparacion (T5)...'
        healthy  = 'Tu equipo ya esta sano: no hay nada que reparar.'
        willFmt  = 'Encontre {0} accion(es) que conviene aplicar:'
        doneFmt  = 'Reparacion aplicada. Revisa el resultado abajo.'
        needAdmin = 'Para aplicar cambios necesitas ejecutar HVGuard como administrador. Ahora estas en modo solo lectura: puedes ver que haria, pero no aplicarlo.'
        confirm  = 'Voy a reactivar tus protecciones, cerrar las puertas que usa el crack, y limpiar sus rastros. Todo va en la direccion de MAS seguridad. Nada desactiva una proteccion. Continuar?'
        confirmTitle = 'Confirmar reparacion'
        reboot   = 'Hace falta REINICIAR para que los cambios surtan efecto.'
        uefi     = 'Hay pasos MANUALES pendientes (por ejemplo, activar Secure Boot fuera de Windows, o un driver que esta en ejecucion: reinicia y vuelve a aplicar).'
        recheck  = 'Tras reiniciar, vuelve a "Comprobar" para confirmar que todo quedo en verde.'
        errFmt   = 'Hubo errores durante la reparacion. Revisa los detalles.'
        stepPrefix = 'Paso'
        chooseHdr  = 'Elige que quieres restaurar. Marca o desmarca cada opcion de la lista; abre "Que es esto?" si no sabes que hace. Nada de esto desactiva una proteccion: todo va hacia MAS seguridad.'
        whatIs     = 'Que es esto?'
        techLabel  = 'Detalle tecnico'
        applySelFmt = 'Aplicar lo marcado ({0})'
        selAll     = 'Marcar todo'
        selNone    = 'Desmarcar todo'
        bReboot    = 'Necesita reiniciar'
        bNow       = 'Efecto inmediato'
        bKey       = 'Clave contra el bypass'
        manualHdr  = 'Esto NO se puede automatizar: lo tienes que hacer tu'
        noSel      = 'No has marcado ninguna opcion. Marca al menos una para poder aplicar.'
        confirmSelFmt = "Voy a aplicar {0} cambio(s) que has marcado:`n`n{1}`n`nTodo va en la direccion de MAS seguridad. Nada desactiva una proteccion. Continuar?"
        curState   = 'Estado medido:'
        affectedFmt = '{0} elemento(s) afectado(s):'
        skippedFmt = 'No aplicados porque no los marcaste: {0}'
    }
    $en = @{
        title    = 'Repair your protections'
        intro    = 'Restores, in the safe direction, what the crack weakens: turns your protections back on and cleans up its traces. First it shows what it WOULD do without changing anything, and YOU choose what to restore, option by option. It only changes something when you click "Apply selected".'
        btnScan  = 'Show what it would do (no changes)'
        btnApply = 'Apply changes'
        scanning = 'Analyzing what to repair (T5 in simulation mode)...'
        applying = 'Applying the repair (T5)...'
        healthy  = 'Your PC is already healthy: nothing to repair.'
        willFmt  = 'Found {0} action(s) worth applying:'
        doneFmt  = 'Repair applied. See the result below.'
        needAdmin = 'To apply changes you must run HVGuard as administrator. You are in read-only mode now: you can preview, but not apply.'
        confirm  = 'I will turn your protections back on, close the doors the crack uses, and clean up its traces. Everything goes toward MORE security. Nothing disables a protection. Continue?'
        confirmTitle = 'Confirm repair'
        reboot   = 'A RESTART is required for the changes to take effect.'
        uefi     = 'There are MANUAL steps pending (for example, turning on Secure Boot outside Windows, or a driver that is currently running: reboot and apply again).'
        recheck  = 'After restarting, go back to "Check" to confirm everything turned green.'
        errFmt   = 'There were errors during the repair. See details.'
        stepPrefix = 'Step'
        chooseHdr  = 'Choose what you want to restore. Tick or untick each option below; open "What is this?" if you are not sure what it does. None of this disables a protection: everything goes toward MORE security.'
        whatIs     = 'What is this?'
        techLabel  = 'Technical detail'
        applySelFmt = 'Apply selected ({0})'
        selAll     = 'Select all'
        selNone    = 'Select none'
        bReboot    = 'Needs a restart'
        bNow       = 'Takes effect now'
        bKey       = 'Key against the bypass'
        manualHdr  = 'This CANNOT be automated: you have to do it yourself'
        noSel      = 'You have not selected anything. Tick at least one option to apply.'
        confirmSelFmt = "I will apply {0} change(s) you selected:`n`n{1}`n`nEverything goes toward MORE security. Nothing disables a protection. Continue?"
        curState   = 'Measured state:'
        affectedFmt = '{0} affected item(s):'
        skippedFmt = 'Not applied because you did not select them: {0}'
    }
    if ($Lang -eq 'en') { return $en } else { return $es }
}

function Get-HvgM2Friendly {
    param([string]$Id, [string]$Lang)
    $map_es = @{
        R1  = 'Activar el area protegida dentro de Windows'
        R1b = 'Quitar el bloqueo que impide que arranque esa area protegida'
        R2  = 'Reactivar la proteccion profunda'
        R3  = 'Desactivar el modo de desarrollador que salta el control de identidad'
        R3b = 'Reactivar el control de identidad para todos los drivers'
        R4  = 'Permitir que Windows encienda su modo especial de seguridad'
        R5  = 'Borrar la marca que dejo el crack'
        R6  = 'Impedir que el driver residual del crack se vuelva a cargar'
        R7  = 'Activar Secure Boot (paso manual fuera de Windows)'
        R8  = 'Activar la proteccion de Microsoft contra drivers con fallos conocidos'
        R9  = 'Borrar del equipo los ficheros que dejo el crack'
    }
    $map_en = @{
        R1  = 'Turn on the protected area inside Windows'
        R1b = 'Remove the block keeping that protected area from starting'
        R2  = 'Turn the deep protection back on'
        R3  = 'Turn off developer mode that skips driver ID checks'
        R3b = 'Turn ID checks back on for every driver'
        R4  = 'Allow Windows to turn on its special security mode'
        R5  = 'Erase the marker the crack left behind'
        R6  = 'Stop the leftover crack driver from loading again'
        R7  = 'Turn on Secure Boot (a manual step outside Windows)'
        R8  = 'Turn on Microsoft''s protection against known risky drivers'
        R9  = 'Delete the crack''s leftover files from your PC'
    }
    $m = if ($Lang -eq 'en') { $map_en } else { $map_es }
    if ($m.ContainsKey($Id)) { return $m[$Id] } else { return $Id }
}

function Get-HvgM2Explain {
    <#
    .SYNOPSIS  Plain-language explanation of each repair step, so the user can
               DECIDE with good judgement what to restore and what not to.
    .DESCRIPTION
               Fixed structure per step: WHAT IT IS (what protection it is, in human terms) / WHY IT MATTERS
               (how it relates to the bypass) / WHAT I WILL DO (the concrete change and its reversibility).
               No untranslated jargon and no promising absolute security.
    #>
    param([string]$Id, [string]$Lang)
    $es = @{
        R1 = "QUE ES: Windows puede encerrar su parte mas sensible - el centro que controla todo tu equipo - en una sala propia, separada del resto del sistema. Este paso es el que construye esa sala; el siguiente paso es el cierre de su puerta.`n`nPOR QUE IMPORTA: el crack necesita esa sala apagada, porque todo lo demas que hace depende de eso. Es parte de la unica familia de proteccion que la tecnica no consigue saltar.`n`nDONDE PUEDES VERLO: abre Informacion del sistema (busca msinfo32) y mira la linea llamada Virtualization-based security.`n`nQUE VOY A HACER: reactivarla. No borra nada ni afecta a tus programas. Necesita reiniciar."
        R1b = "QUE ES: Windows esta configurado para abrir esa sala solo si Secure Boot esta activo. Como Secure Boot esta apagado en este equipo, esa condicion nunca se puede cumplir: la sala queda marcada como activada en el papel, pero nunca llega a abrirse de verdad.`n`nPOR QUE IMPORTA: quitar esa condicion es lo que permite que la sala se abra y haga su trabajo de verdad. Importante: esto NO apaga nada. Secure Boot se queda exactamente como estaba; solo dejamos de exigirlo antes de permitir que la sala se abra.`n`nDONDE PUEDES VERLO: abre Informacion del sistema (busca msinfo32) y mira la linea llamada Virtualization-based security.`n`nQUE VOY A HACER: quitar esa condicion imposible de cumplir para que la sala pueda abrirse de verdad."
        R2 = "QUE ES: Windows guarda su parte mas sensible - el centro que controla todo tu equipo - en una sala sellada. Esto es el cierre de esa puerta: solo entra software con una identidad verificada.`n`nPOR QUE IMPORTA: con el cierre apagado, un programa puede entrar en esa sala, ver todo lo que escribes y esconderse de tu antivirus. Es la unica proteccion que el crack no consigue saltar, y por eso te pide que la apagues.`n`nDONDE PUEDES VERLO: Seguridad de Windows > Seguridad del dispositivo > Aislamiento del nucleo > Integridad de memoria.`n`nQUE VOY A HACER: reactivarlo. Necesita reiniciar. Si algun driver muy antiguo resulta incompatible, Windows te avisara y podras revertirlo."
        R3 = "QUE ES: Windows tiene un modo especial pensado para programadores que estan construyendo sus propios drivers, que acepta drivers sin una identidad de confianza en regla.`n`nPOR QUE IMPORTA: es una de las dos vias por las que un driver sin confianza puede colarse en la parte mas protegida de Windows. El crack activa este modo para poder cargar su propio driver.`n`nDONDE PUEDES VERLO: no hay pantalla de configuracion para esto. Mientras esta activo, Windows muestra en pantalla las palabras Test Mode en la esquina inferior derecha del escritorio.`n`nQUE VOY A HACER: apagarlo y devolver a Windows su comportamiento normal. Necesita reiniciar."
        R3b = "QUE ES: Windows tiene un interruptor de arranque que, si esta activado, le dice que no compruebe la identidad de ningun driver - ni siquiera la comprobacion normal que esta activada por defecto.`n`nPOR QUE IMPORTA: es la otra de las dos vias por las que un driver sin confianza puede entrar en la parte mas protegida de Windows.`n`nDONDE PUEDES VERLO: no hay ningun interruptor visible para esto en Windows; es un ajuste interno.`n`nQUE VOY A HACER: apagarlo y devolver a Windows su comportamiento normal. Necesita reiniciar."
        R4 = "QUE ES: hay un ajuste de arranque que decide si Windows tiene permiso para usar su modo extra protegido. Si esta apagado, ninguna de las dos protecciones anteriores puede funcionar, aunque las actives.`n`nPOR QUE IMPORTA: sin esto, activar las otras protecciones no serviria de nada.`n`nDONDE PUEDES VERLO: abre Informacion del sistema (busca msinfo32) y mira la linea llamada Virtualization-based security.`n`nQUE VOY A HACER: ponerlo en su valor normal de Windows, para que el modo extra protegido tenga permiso de arrancar."
        R5 = "QUE ES: el crack deja una pequena marca en tu equipo para recordar que protecciones apago, y poder deshacer su propio trabajo mas adelante.`n`nPOR QUE IMPORTA: encontrar esta marca es la prueba de que la tecnica se preparo o se uso en este equipo. Por si sola no es peligrosa: es solo un rastro.`n`nDONDE PUEDES VERLO: no hay interruptor ni pantalla visible para esto; vive en un ajuste interno, no en ningun menu.`n`nQUE VOY A HACER: borrarla. Los pasos anteriores ya restauran las protecciones reales, asi que esta marca ya no hace falta. Efecto inmediato, sin necesidad de reiniciar."
        R6 = "QUE ES: uno de los drivers del crack quedo registrado ante Windows como un servicio oficial del sistema, no solo como un fichero suelto.`n`nPOR QUE IMPORTA: mientras siga registrado, Windows podria volver a cargarlo la proxima vez que arranque tu equipo.`n`nDONDE PUEDES VERLO: no hay interruptor visible para esto; es un ajuste interno, no esta en ningun menu.`n`nQUE VOY A HACER: por defecto lo marco para que no pueda volver a arrancar, sin borrar el fichero, asi que esto se puede deshacer si hace falta. Si en este momento esta en marcha, no lo toco: forzarlo a detenerse podria bloquear tu equipo. En ese caso, reinicia y repite la reparacion."
        R7 = "QUE ES: tu equipo comprueba, antes incluso de que arranque Windows, que el proceso de inicio no ha sido manipulado. Esa comprobacion ocurre totalmente fuera de Windows, en la propia pantalla de configuracion de tu equipo.`n`nPOR QUE IMPORTA: anade una capa extra de proteccion al propio inicio del equipo. Importante: la proteccion profunda de los pasos anteriores no necesita esto para protegerte, asi que puedes seguir protegido aunque esto siga apagado.`n`nDONDE PUEDES VERLO: abre Informacion del sistema (busca msinfo32) y mira la linea llamada Secure Boot State.`n`nQUE VOY A HACER: nada - esto no lo puedo cambiar yo.`n`nPOR QUE NO PUEDO HACERLO: este ajuste solo se puede leer desde Windows, nunca cambiar desde Windows. El interruptor real vive en la propia pantalla de configuracion de tu equipo, fuera de Windows, y normalmente exige que alguien este delante del teclado cuando el equipo reinicia. Ni esta herramienta ni el propio crack pueden encenderlo ni apagarlo desde dentro de Windows. Solo puedo decirte donde encontrarlo."
        R8 = "QUE ES: Microsoft mantiene una lista de drivers reales y legitimos que resultaron tener fallos graves - fallos que un atacante puede aprovechar para meter su propio codigo en la parte mas protegida de Windows sin necesitar ninguna identidad valida.`n`nPOR QUE IMPORTA: cierra una puerta lateral muy usada hacia esa zona protegida, una que no depende de firmas ni de modos de desarrollador.`n`nDONDE PUEDES VERLO: Seguridad de Windows > Seguridad del dispositivo > Aislamiento del nucleo > Lista de bloqueo de controladores vulnerables de Microsoft.`n`nQUE VOY A HACER: activarla. Necesita reiniciar."
        R9 = "QUE ES: copias sueltas de los propios ficheros del crack, olvidadas en carpetas normales como Temp, Descargas o el Escritorio - incluido el propio fichero del driver sin firma, que el crack deja ahi antes de intentar cargarlo.`n`nPOR QUE IMPORTA: mientras estan ahi quietos, no hacen nada por si solos. Pero son la prueba de que el crack se uso, y uno de ellos es el fichero real que el crack necesita para funcionar.`n`nDONDE PUEDES VERLO: no hay interruptor para esto; son solo ficheros en tu disco, que se pueden ver como cualquier otro fichero.`n`nQUE VOY A HACER: borrar unicamente los ficheros cuyo nombre coincide exactamente con una lista conocida de componentes del crack. No toco nada mas tuyo. Efecto inmediato."
    }
    $en = @{
        R1 = "WHAT IT IS: Windows can seal off its most sensitive part - the core that controls your whole PC - into its own protected room, cut off from everything else. This item builds that room; the next item is the lock on its door.`n`nWHY IT MATTERS: the crack needs this room switched off, because everything else it does depends on that. It is part of the one family of protection the technique cannot get around.`n`nWHERE YOU CAN SEE IT: open System Information (search for msinfo32) and look at the line named Virtualization-based security.`n`nWHAT I WILL DO: turn it back on. It deletes nothing and does not touch your programs. It needs a restart."
        R1b = "WHAT IT IS: Windows is set to only actually turn on that protected room if Secure Boot is on. Since Secure Boot is off on this PC, that condition can never be met - the room stays switched on on paper, but never really opens.`n`nWHY IT MATTERS: removing that condition is what lets the room actually open and do its job. Important: this does not turn anything off. Secure Boot is left exactly as it was; we only stop requiring it before the room is allowed to open.`n`nWHERE YOU CAN SEE IT: open System Information (search for msinfo32) and look at the line named Virtualization-based security.`n`nWHAT I WILL DO: remove that impossible condition so the room can actually open."
        R2 = "WHAT IT IS: Windows keeps its most sensitive part - the core that controls your whole PC - in a sealed room. This is the lock on that door: only software with a verified ID gets in.`n`nWHY IT MATTERS: with the lock off, a program can move into that room, watch everything you type, and hide from your antivirus. This is the one protection the crack cannot get around, which is why it asks you to switch it off.`n`nWHERE YOU CAN SEE IT: Windows Security > Device security > Core isolation > Memory integrity.`n`nWHAT I WILL DO: switch it back on. It needs a restart. If a very old device driver turns out to be incompatible, Windows will tell you and you can undo it."
        R3 = "WHAT IT IS: Windows has a special mode meant for programmers who are building their own drivers, which accepts drivers that do not have a proper, trusted ID.`n`nWHY IT MATTERS: it is one of two ways an untrusted driver can sneak into the most protected part of Windows. The crack turns this mode on to get its own driver loaded.`n`nWHERE YOU CAN SEE IT: there is no settings page for this one. While it is on, Windows shows a Test Mode watermark in the bottom-right corner of your desktop.`n`nWHAT I WILL DO: turn it off and put Windows back to its normal behaviour. It needs a restart."
        R3b = "WHAT IT IS: Windows has a boot switch that, when turned on, tells it not to check any driver's ID at all - not even the normal check that is on by default.`n`nWHY IT MATTERS: it is the other of the two ways an untrusted driver can get into the most protected part of Windows.`n`nWHERE YOU CAN SEE IT: there is no visible switch for this one anywhere in Windows; it is an internal setting.`n`nWHAT I WILL DO: turn it off and put Windows back to its normal behaviour. It needs a restart."
        R4 = "WHAT IT IS: there is a boot setting that decides whether Windows is even allowed to start its extra-protected mode. If it is switched off, neither of the two protections above can work, no matter what else you fix.`n`nWHY IT MATTERS: without this, turning the other protections on would not achieve anything.`n`nWHERE YOU CAN SEE IT: open System Information (search for msinfo32) and look at the line named Virtualization-based security.`n`nWHAT I WILL DO: set it to its normal Windows value, so the extra-protected mode is allowed to start."
        R5 = "WHAT IT IS: the crack leaves behind a small marker on your PC to remember which protections it switched off, so it can undo its own work later.`n`nWHY IT MATTERS: finding this marker is proof the technique was set up or used on this PC. By itself it does nothing harmful - it is just a trace.`n`nWHERE YOU CAN SEE IT: there is no visible switch or screen for this; it lives in an internal setting, not in any menu.`n`nWHAT I WILL DO: erase it. The steps above already restore the real protections, so this marker is not needed any more. It takes effect immediately, no restart needed."
        R6 = "WHAT IT IS: one of the crack's drivers was left registered with Windows as an official system service, not just sitting there as a file.`n`nWHY IT MATTERS: as long as it stays registered, Windows could load it again the next time your PC starts.`n`nWHERE YOU CAN SEE IT: there is no visible switch for this; it is an internal setting, not in any menu.`n`nWHAT I WILL DO: by default, mark it so it cannot start any more, without deleting the file - so this can be undone if needed. If it happens to be running right now, I will not touch it: forcing it to stop could crash your PC. In that case, restart and run the repair again."
        R7 = "WHAT IT IS: your PC checks, before Windows even starts, that the startup process has not been tampered with. This check happens entirely outside Windows, in your PC's own setup screen.`n`nWHY IT MATTERS: it adds an extra layer of protection to the startup process itself. Importantly, the deep protection from the earlier items does not need this to protect you, so you can still be protected even while this stays off.`n`nWHERE YOU CAN SEE IT: open System Information (search for msinfo32) and look at the line named Secure Boot State.`n`nWHAT I WILL DO: nothing - this is not something I can change.`n`nWHY I CANNOT DO IT: this setting can only be read from Windows, never changed from Windows. The real switch lives in your PC's own setup screen, outside Windows, and normally needs someone at the keyboard when the PC restarts. Neither this tool nor the crack itself can turn it on or off from inside Windows. I can only tell you where to find it."
        R8 = "WHAT IT IS: Microsoft keeps a list of real, legitimate drivers that turned out to have serious flaws - flaws attackers can abuse to sneak their own code into the most protected part of Windows without needing a valid ID at all.`n`nWHY IT MATTERS: it closes a common side door into that protected area, one that does not depend on signatures or developer modes at all.`n`nWHERE YOU CAN SEE IT: Windows Security > Device security > Core isolation > Microsoft vulnerable driver blocklist.`n`nWHAT I WILL DO: turn it on. It needs a restart."
        R9 = "WHAT IT IS: loose copies of the crack's own files, left behind in ordinary folders like Temp, Downloads or your Desktop - including the actual unsigned driver file itself, which the crack drops there before trying to load it.`n`nWHY IT MATTERS: sitting there, they do nothing by themselves. But they are evidence the crack was used, and one of them is the real file the crack needs to work.`n`nWHERE YOU CAN SEE IT: there is no switch for this; these are just files sitting on your disk, found the same way as any other file.`n`nWHAT I WILL DO: delete only the files whose exact name matches a known list of the crack's components. Nothing else of yours is touched. It takes effect immediately."
    }
    $m = if ($Lang -eq 'en') { $en } else { $es }
    if ($m.ContainsKey($Id)) { return $m[$Id] } else { return '' }
}

function Get-HvgM2Tech {
    <#
    .SYNOPSIS  LAYER 3: the technical detail behind each repair step.
    .DESCRIPTION
               Exact registry values, BCD elements, security properties and commands, for whoever wants
               to verify or audit what the tool does - and so that this detail does NOT sit on the
               reading path of a non-technical user. It lives behind its own quieter "Technical detail"
               dropdown; Layers 1 and 2 stay jargon-free (see tools/check-plain-language.ps1).
               Identifiers, paths and property names are deliberately identical in both languages.
    #>
    param([string]$Id, [string]$Lang)
    $es = @{
        R1Tech = "Pone EnableVirtualizationBasedSecurity=1 en`nHKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard`nRequiere reinicio. RequirePlatformSecurityFeatures solo se fija si la plataforma ofrece Secure Boot (si no, ver R1b)."
        R1bTech = "Retira RequirePlatformSecurityFeatures de`nHKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard`n(o baja 3 -> 1 si solo falta proteccion DMA).`nCausa: Win32_DeviceGuard.RequiredSecurityProperties incluia 2=SecureBoot, ausente de AvailableSecurityProperties, dejando VirtualizationBasedSecurityStatus=1 (enabled, not running) y SecurityServicesRunning vacio. Requiere reinicio."
        R2Tech = "Pone Enabled=1 en`nHKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity`nHVCI se aplica desde VTL1 (el hipervisor raiz), por lo que codigo en ring 0 no puede desactivarlo. Requiere reinicio."
        R3Tech = "Ejecuta: bcdedit /set testsigning off`nLee el elemento testsigning de la entrada BCD {current}. Requiere reinicio."
        R3bTech = "Ejecuta: bcdedit /set nointegritychecks off`nElemento BCD de {current}. Windows lo ignora cuando Secure Boot esta activo, pero se normaliza igualmente. Requiere reinicio."
        R4Tech = "Ejecuta: bcdedit /set hypervisorlaunchtype Auto`nCon el valor Off, el hipervisor de Windows no arranca y VBS/HVCI no pueden ejecutarse aunque esten habilitados. Requiere reinicio."
        R5Tech = "Borra recursivamente la clave`nHKLM\SOFTWARE\ManageVBS`nEfecto inmediato, sin reinicio. Es el marcador que crea el VBS.cmd del bypass para poder revertir."
        R6Tech = "Por defecto: sc.exe config <servicio> start= disabled (cuarentena, no borra el fichero).`nCon -RemoveResidualDriver: sc.exe delete <servicio>.`nSolo actua si Win32_SystemDriver.State no es Running. Lista blanca de nombres: simplesvm, hyperkd, hyperhv, hyperevade."
        R7Tech = "No automatizable. La variable UEFI SecureBoot es BS+RT de SOLO LECTURA en runtime: el firmware la publica y el SO no puede escribirla. El interruptor vive en el setup del firmware y suele exigir presencia fisica. Se lee con Confirm-SecureBootUEFI; SetupMode indica si hay PK enrolada.`nAtajo al firmware: shutdown /r /fw /t 0`nCambiarlo altera las medidas de arranque (PCR 7): con BitLocker activo puede pedir la clave de recuperacion."
        R8Tech = "Pone VulnerableDriverBlocklistEnable=1 en`nHKLM\SYSTEM\CurrentControlSet\Control\CI\Config`nEs la lista de Microsoft contra BYOVD (bring your own vulnerable driver). Requiere reinicio."
        R9Tech = "Borra ficheros cuyo NOMBRE coincide con la lista de componentes conocidos (SimpleSvm.sys, hyperkd.sys, hyperhv.dll, hyperevade.dll, hypervisor-launcher.exe, VBS.cmd, DenuvOwO.nfo, EfiGuardDxe.efi, Loader.efi) bajo %TEMP%, Descargas, Escritorio y %ProgramData% con profundidad 3, mas carpetas .tmp* que queden vacias. Efecto inmediato."
    }
    $en = @{
        R1Tech = "Sets EnableVirtualizationBasedSecurity=1 in`nHKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard`nRequires a restart. RequirePlatformSecurityFeatures is only set if the platform offers Secure Boot (otherwise see R1b)."
        R1bTech = "Removes RequirePlatformSecurityFeatures from`nHKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard`n(or lowers 3 -> 1 if only DMA protection is missing).`nCause: Win32_DeviceGuard.RequiredSecurityProperties included 2=SecureBoot, absent from AvailableSecurityProperties, leaving VirtualizationBasedSecurityStatus=1 (enabled, not running) and SecurityServicesRunning empty. Requires a restart."
        R2Tech = "Sets Enabled=1 in`nHKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity`nHVCI is enforced from VTL1 (the root hypervisor), so ring 0 code cannot switch it off. Requires a restart."
        R3Tech = "Runs: bcdedit /set testsigning off`nReads the testsigning element of the BCD {current} entry. Requires a restart."
        R3bTech = "Runs: bcdedit /set nointegritychecks off`nBCD element of {current}. Windows ignores it while Secure Boot is on, but it is normalized anyway. Requires a restart."
        R4Tech = "Runs: bcdedit /set hypervisorlaunchtype Auto`nWith the value Off the Windows hypervisor does not start, so VBS/HVCI cannot run even when enabled. Requires a restart."
        R5Tech = "Recursively deletes the key`nHKLM\SOFTWARE\ManageVBS`nImmediate, no restart. It is the marker the bypass VBS.cmd creates so it can revert."
        R6Tech = "By default: sc.exe config <service> start= disabled (quarantine; the file is not deleted).`nWith -RemoveResidualDriver: sc.exe delete <service>.`nOnly acts if Win32_SystemDriver.State is not Running. Name allowlist: simplesvm, hyperkd, hyperhv, hyperevade."
        R7Tech = "Not automatable. The UEFI SecureBoot variable is BS+RT READ-ONLY at runtime: firmware publishes it and the OS cannot write it. The switch lives in firmware setup and usually requires physical presence. Read with Confirm-SecureBootUEFI; SetupMode tells you whether a PK is enrolled.`nShortcut into firmware: shutdown /r /fw /t 0`nChanging it alters the boot measurements (PCR 7): with BitLocker on it may ask for the recovery key."
        R8Tech = "Sets VulnerableDriverBlocklistEnable=1 in`nHKLM\SYSTEM\CurrentControlSet\Control\CI\Config`nThis is Microsoft's blocklist against BYOVD (bring your own vulnerable driver). Requires a restart."
        R9Tech = "Deletes files whose NAME matches the known-component list (SimpleSvm.sys, hyperkd.sys, hyperhv.dll, hyperevade.dll, hypervisor-launcher.exe, VBS.cmd, DenuvOwO.nfo, EfiGuardDxe.efi, Loader.efi) under %TEMP%, Downloads, Desktop and %ProgramData% at depth 3, plus any .tmp* folder left empty. Immediate."
    }
    $m = if ($Lang -eq 'en') { $en } else { $es }
    $k = $Id + 'Tech'
    if ($m.ContainsKey($k)) { return $m[$k] } else { return '' }
}

function Get-HvgM2Selection {
    <# Step IDs that the user has left CHECKED. This is the allowlist passed to T5 -Only. #>
    $ids = @()
    foreach ($c in @($script:HvgM2.Choices)) {
        if ($c -and $c.Check -and $true -eq $c.Check.IsChecked) { $ids += [string]$c.Id }
    }
    return $ids
}

function Update-HvgM2ApplyState {
    <# Refreshes the "Apply selected (N)" button's counter and its enabled state. #>
    $s = $script:HvgM2.S
    $n = @(Get-HvgM2Selection).Count
    if ($script:HvgM2.BtnApply) {
        $script:HvgM2.BtnApply.Content = ($s.applySelFmt -f $n)
        $script:HvgM2.BtnApply.IsEnabled = ($n -gt 0) -and $script:HvgM2.CanApply
    }
}

function Set-HvgM2AllChecks {
    param([bool]$On)
    foreach ($c in @($script:HvgM2.Choices)) {
        if ($c -and $c.Check -and $c.Check.IsEnabled) { $c.Check.IsChecked = $On }
    }
    Update-HvgM2ApplyState
}

function Show-HvgM2Result {
    param($T5, [bool]$IsApply)
    $s = $script:HvgM2.S; $lang = $script:HvgCtx.Lang
    $panel = $script:HvgM2.Results
    $panel.Children.Clear()
    $script:HvgM2.Choices = @()          # rebuilt on every scan
    if (-not $T5) {
        [void]$panel.Children.Add((New-HvgParagraph -Text $s.errFmt -Color '#D64545'))
        $script:HvgM2.CanApply = $false; if ($script:HvgM2.BtnApply) { $script:HvgM2.BtnApply.IsEnabled = $false }
        return
    }
    $steps = @(); if ($T5.steps) { $steps = @($T5.steps) }
    $needed = @($steps | Where-Object { $_.needed })
    $wouldFix = @($steps | Where-Object { "$($_.status)" -eq 'WOULD_FIX' })
    $errs = @($steps | Where-Object { "$($_.status)" -eq 'ERROR' })
    $skipped = @($steps | Where-Object { "$($_.status)" -eq 'SKIPPED' })
    $manual = @($steps | Where-Object { $_.manual -and $_.needed })

    # Grouped by ID: R6/R9 can bring SEVERAL entries (one per driver or per file) and the user
    # must see ONE single option per concept, with the affected items listed inside.
    $order = @(); $groups = @{}
    foreach ($st in $needed) {
        $id = "$($st.id)"
        if (-not $groups.ContainsKey($id)) { $groups[$id] = @(); $order += $id }
        $groups[$id] += $st
    }

    if ($needed.Count -eq 0) {
        [void]$panel.Children.Add((New-HvgEvidenceCard -Level ok -Title $s.healthy -Detail ''))
        $script:HvgM2.CanApply = $false
    }
    elseif (-not $IsApply) {
        # ---------- CHOICE MODE: the user decides WHAT gets restored ----------
        [void]$panel.Children.Add((New-HvgParagraph -Text ($s.willFmt -f $order.Count)))
        [void]$panel.Children.Add((New-HvgParagraph -Text $s.chooseHdr -Color '#6B7280' -FontSize 12))

        $selRow = [System.Windows.Controls.StackPanel]::new()
        $selRow.Orientation = [System.Windows.Controls.Orientation]::Horizontal
        $selRow.Margin = [System.Windows.Thickness]::new(0, 0, 0, 8)
        foreach ($pair in @(@($s.selAll, $true), @($s.selNone, $false))) {
            $b = [System.Windows.Controls.Button]::new()
            $b.Content = $pair[0]; $b.Tag = $pair[1]
            $b.Margin = [System.Windows.Thickness]::new(0, 0, 8, 0)
            $b.Padding = [System.Windows.Thickness]::new(10, 3, 10, 3)
            $b.Add_Click({ Set-HvgM2AllChecks -On ([bool]$this.Tag) })
            [void]$selRow.Children.Add($b)
        }
        [void]$panel.Children.Add($selRow)

        $manualGroups = @()
        foreach ($id in $order) {
            $entries = @($groups[$id])
            $allManual = (@($entries | Where-Object { $_.manual }).Count -eq $entries.Count)
            if ($allManual) { $manualGroups += $id; continue }

            $friendly = Get-HvgM2Friendly -Id $id -Lang $lang
            if ($entries.Count -eq 1) {
                $detail = ("{0} {1}" -f $s.curState, [string]$entries[0].observed)
                if ($entries[0].evidence) { $detail += "`n" + [string]$entries[0].evidence }
            } else {
                $detail = ($s.affectedFmt -f $entries.Count) + "`n" +
                          ((@($entries | ForEach-Object { '  - ' + [string]$_.observed })) -join "`n")
            }
            $badges = @()
            $badges += if (@($entries | Where-Object { $_.rebootRequired }).Count -gt 0) { $s.bReboot } else { $s.bNow }
            if ($id -in @('R1', 'R1b', 'R2')) { $badges += $s.bKey }

            $choice = New-HvgStepChoice -Id $id -Title $friendly -What (Get-HvgM2Explain -Id $id -Lang $lang) `
                -Tech (Get-HvgM2Tech -Id $id -Lang $lang) `
                -Detail $detail -Checked $true -Enabled (-not $script:HvgCtx.ReadOnly) `
                -Badges $badges -Level 'warn' -WhatLabel $s.whatIs -TechLabel $s.techLabel
            $choice.Check.Add_Click({ Update-HvgM2ApplyState })
            $script:HvgM2.Choices += $choice
            [void]$panel.Children.Add($choice.Element)
        }

        # Steps that CANNOT be automated (Secure Boot in UEFI, a running driver): they are explained, not
        # offered as a checkbox, because ticking something the tool cannot do would be misleading.
        if ($manualGroups.Count -gt 0) {
            [void]$panel.Children.Add((New-HvgParagraph -Text $s.manualHdr -Color '#92400E'))
            foreach ($id in $manualGroups) {
                foreach ($st in @($groups[$id])) {
                    $friendly = Get-HvgM2Friendly -Id $id -Lang $lang
                    $d = (Get-HvgM2Explain -Id $id -Lang $lang)
                    $d += "`n`n" + ("{0} {1}" -f $s.curState, [string]$st.observed) + "`n" + [string]$st.evidence
                    [void]$panel.Children.Add((New-HvgEvidenceCard -Level info -Title $friendly -Detail $d))
                }
            }
        }
        $script:HvgM2.CanApply = ($wouldFix.Count -gt 0) -and (-not $script:HvgCtx.ReadOnly)
    }
    else {
        # ---------- RESULT MODE: what was applied, what was skipped, what is pending ----------
        [void]$panel.Children.Add((New-HvgParagraph -Text $s.doneFmt))
        foreach ($id in $order) {
            foreach ($st in @($groups[$id])) {
                $friendly = Get-HvgM2Friendly -Id $id -Lang $lang
                $status = "$($st.status)"
                $lvl = switch ($status) { 'FIXED' { 'ok' } 'ERROR' { 'bad' } 'SKIPPED' { 'info' } 'MANUAL' { 'warn' } default { 'warn' } }
                $detail = [string]$st.evidence
                if ($st.observed) { $detail = ("{0}`n{1}" -f [string]$st.observed, [string]$st.evidence) }
                [void]$panel.Children.Add((New-HvgEvidenceCard -Level $lvl `
                    -Title ("{0} {1} [{2}]: {3}" -f $s.stepPrefix, $id, $status, $friendly) -Detail $detail))
            }
        }
        $needReboot = $false; try { $needReboot = [bool]$T5.rebootRequired } catch { }
        if ($needReboot) { [void]$panel.Children.Add((New-HvgEvidenceCard -Level warn -Title $s.reboot -Detail $s.recheck)) }
        if ($manual.Count -gt 0) { [void]$panel.Children.Add((New-HvgEvidenceCard -Level warn -Title $s.uefi -Detail '')) }
        if ($skipped.Count -gt 0) {
            $ids = (@($skipped | ForEach-Object { "$($_.id)" }) | Select-Object -Unique) -join ', '
            [void]$panel.Children.Add((New-HvgEvidenceCard -Level info -Title ($s.skippedFmt -f $ids) -Detail ''))
        }
        if ($errs.Count -gt 0) { [void]$panel.Children.Add((New-HvgParagraph -Text $s.errFmt -Color '#D64545')) }
        $script:HvgM2.CanApply = $false
    }
    Update-HvgM2ApplyState
}

function Invoke-HvgM2Scan {
    # Asynchronous: T5 in dry-run (without -Apply). Does NOT block the window.
    $s = $script:HvgM2.S
    Set-HvgBusy -On $true -Text $s.scanning
    if ($script:HvgM2.BtnScan) { $script:HvgM2.BtnScan.IsEnabled = $false }
    if ($script:HvgM2.BtnApply) { $script:HvgM2.BtnApply.IsEnabled = $false }
    Invoke-HvgToolAsync -ScriptName T5 -TimeoutSec 180 `
        -OnTick { param($sec) Set-HvgStatusBar -Text ("{0} ({1}s)" -f $script:HvgM2.S.scanning, $sec) } `
        -OnDone {
        param($r)
        try { Show-HvgM2Result -T5 $r.Result -IsApply $false; Set-HvgStatusBar -Text $script:HvgM2.S.title }
        catch { Set-HvgStatusBar -Text ("M2: " + $_.Exception.Message) }
        finally { Set-HvgBusy -On $false -Text ''; if ($script:HvgM2.BtnScan) { $script:HvgM2.BtnScan.IsEnabled = $true } }
    }
}

function Invoke-HvgM2Apply {
    $s = $script:HvgM2.S
    if ($script:HvgCtx.ReadOnly) { [System.Windows.MessageBox]::Show($s.needAdmin, 'HVGuard', 'OK', 'Information') | Out-Null; return }
    # Only what the user has CHECKED gets applied. The confirmation lists exactly that.
    $sel = @(Get-HvgM2Selection)
    if ($sel.Count -eq 0) { [System.Windows.MessageBox]::Show($s.noSel, 'HVGuard', 'OK', 'Information') | Out-Null; return }
    $lang = $script:HvgCtx.Lang
    $list = (@($sel | ForEach-Object { '  - ' + (Get-HvgM2Friendly -Id $_ -Lang $lang) })) -join "`n"
    if ([System.Windows.MessageBox]::Show(($s.confirmSelFmt -f $sel.Count, $list), $s.confirmTitle, 'YesNo', 'Warning') -ne 'Yes') { return }
    # Asynchronous: T5 -Apply -Force -Only <checked ids>. Does NOT block the window.
    Set-HvgBusy -On $true -Text $s.applying
    if ($script:HvgM2.BtnScan) { $script:HvgM2.BtnScan.IsEnabled = $false }
    if ($script:HvgM2.BtnApply) { $script:HvgM2.BtnApply.IsEnabled = $false }
    Invoke-HvgToolAsync -ScriptName T5 -Params @{ Apply = $true; Force = $true; Only = ($sel -join ',') } -TimeoutSec 600 `
        -OnTick { param($sec) Set-HvgStatusBar -Text ("{0} ({1}s)" -f $script:HvgM2.S.applying, $sec) } `
        -OnDone {
        param($r)
        try { Show-HvgM2Result -T5 $r.Result -IsApply $true; Set-HvgStatusBar -Text $script:HvgM2.S.doneFmt }
        catch { Set-HvgStatusBar -Text ("M2: " + $_.Exception.Message) }
        finally { Set-HvgBusy -On $false -Text ''; if ($script:HvgM2.BtnScan) { $script:HvgM2.BtnScan.IsEnabled = $true } }
    }
}

function Initialize-HvgModule_M2Repair {
    param($Ctx)
    $panel = $Ctx.Window.FindName('PanelRepair')
    $panel.Children.Clear()
    $s = Get-HvgM2Strings -Lang $Ctx.Lang
    $script:HvgM2.S = $s
    $script:HvgM2.Panel = $panel

    $root = [System.Windows.Controls.StackPanel]::new()
    $root.Margin = [System.Windows.Thickness]::new(4)

    [void]$root.Children.Add((New-HvgHeading -Text $s.title))
    [void]$root.Children.Add((New-HvgParagraph -Text $s.intro))

    $btnRow = [System.Windows.Controls.StackPanel]::new()
    $btnRow.Orientation = [System.Windows.Controls.Orientation]::Horizontal
    $btnRow.Margin = [System.Windows.Thickness]::new(0, 4, 0, 10)

    $btnScan = [System.Windows.Controls.Button]::new()
    $btnScan.Content = $s.btnScan; $btnScan.MinWidth = 220; $btnScan.MinHeight = 40
    $btnScan.Margin = [System.Windows.Thickness]::new(0, 0, 10, 0)
    $btnScan.Add_Click({ Invoke-HvgM2Scan })
    [void]$btnRow.Children.Add($btnScan)
    $script:HvgM2.BtnScan = $btnScan

    $btnApply = [System.Windows.Controls.Button]::new()
    $btnApply.Content = $s.btnApply; $btnApply.MinWidth = 150; $btnApply.MinHeight = 40
    $btnApply.FontWeight = [System.Windows.FontWeights]::SemiBold
    $btnApply.IsEnabled = $false
    $btnApply.Add_Click({ Invoke-HvgM2Apply })
    [void]$btnRow.Children.Add($btnApply)
    $script:HvgM2.BtnApply = $btnApply

    [void]$root.Children.Add($btnRow)

    if ($Ctx.ReadOnly) {
        [void]$root.Children.Add((New-HvgEvidenceCard -Level warn -Title $s.needAdmin -Detail ''))
    }

    [void]$root.Children.Add((New-HvgCopyAllButton -Label $Ctx.T.CopyAll -CopiedText $Ctx.T.Copied -GetContainer { $script:HvgM2.Results }))
    # The scroll comes from the tab's ScrollViewer (Shell.xaml); here just a StackPanel that grows.
    $results = [System.Windows.Controls.StackPanel]::new()
    [void]$root.Children.Add($results)
    $script:HvgM2.Results = $results

    [void]$panel.Children.Add($root)
}
