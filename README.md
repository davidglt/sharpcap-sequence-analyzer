# SharpCap Session Analyzer

Herramienta Python para analizar logs de sesiones de SharpCap y generar un resumen operativo de la captura: exposiciones, dithering, autofocus, correcciones térmicas de foco, meridian flip, recuperación de guiado e incidencias de sesión.

## Funciones

- Detecta el objetivo, cámara, filtros, tipos de frame y exposiciones de la sesión.
- Resume exposiciones científicas y auxiliares, progreso de captura, dithering y autofocus.
- Analiza la configuración y ejecución del meridian flip, incluida la detención y recuperación del guiado y los plate solves posteriores.
- Correlaciona las invocaciones de scripts de foco térmico de SharpCap con logs de Focus Sequencer.
- Genera informes JSON, CSV y TXT en `reports/`.
- Clasifica diagnósticos para mostrar en consola únicamente errores accionables, manteniendo el recuento total de warnings y el detalle completo en el informe JSON.

## Requisitos

- Python 3.10 o posterior.
- Un log de SharpCap (`Log_*.log`).
- Opcionalmente, logs de Focus Sequencer para enriquecer las correcciones térmicas.

No requiere dependencias externas para el uso básico.

## Instalación

```powershell
git clone https://github.com/davidglt/sharpcap-sequence-analyzer.git
cd sharpcap-sequence-analyzer
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

## Configuración

Copia el archivo de ejemplo y adapta las rutas a tu instalación:

```powershell
Copy-Item sharpcap_sequence_analyzer.properties.example sharpcap_sequence_analyzer.properties
```

El archivo local `sharpcap_sequence_analyzer.properties` no debe subirse al repositorio. Configura en él, según corresponda:

- La ruta del log de SharpCap o el directorio donde se encuentran los logs.
- La ruta de los logs de Focus Sequencer.
- Los nombres de los scripts de corrección térmica del tubo principal y del tubo guía.

## Uso

Ejecuta el analizador desde el directorio del proyecto:

```powershell
python sharpcap_sequence_analyzer.py
```

El programa muestra un resumen en consola y escribe tres artefactos con marca temporal en `reports/`:

```text
sharpcap_session_report_YYYYMMDD_HHMMSS.json
sharpcap_focus_corrections_YYYYMMDD_HHMMSS.csv
sharpcap_focus_corrections_YYYYMMDD_HHMMSS.txt
```

## Correcciones térmicas de foco

El analizador detecta las ejecuciones de los scripts de foco térmico iniciadas por SharpCap. Cuando encuentra un bloque correspondiente en los logs de Focus Sequencer, incorpora la telemetría disponible:

- `T`: temperatura del enfocador o sensor asociado, en °C.
- `dT`: variación de temperatura respecto de la referencia, en °C.
- `TCF`: coeficiente térmico usado para calcular la compensación, habitualmente en pasos/°C.
- `corr`: corrección solicitada, en pasos del enfocador.
- `pos`: posición `antes->después` del enfocador.
- `backlash`: indica si el movimiento requirió compensación de backlash.
- `update`: estado de actualización de la posición o del modelo.
- `r`: resultado de la ejecución, por ejemplo `ok`, `min_correction` o `interrupted`.

Ejemplo de salida compacta:

```text
[22:43:00.729633] T=22.3 C; dT=-2.25 C; TCF=-60.29; corr=136; pos=14430->14566; backlash=False; update=ok; r=ok
```

`r=min_correction` significa que Focus Sequencer evaluó una corrección pero decidió no mover el enfocador porque no alcanzaba el umbral configurado o porque el movimiento requerido entraba en la dirección de backlash. Estos eventos se conservan en los informes. Dependiendo del formato de la línea emitida por Focus Sequencer, algunos campos opcionales pueden no estar disponibles y se muestran como `None`.

### Tubo principal y tubo guía

Las correcciones se separan entre tubo principal y tubo guía según el script invocado desde SharpCap. Para enriquecer ambos flujos, mantén logs de Focus Sequencer diferenciados y configurados con la convención de nombres que use tu instalación. Si no existe un bloque coincidente para una ejecución —por ejemplo, al analizar una sesión anterior a la separación de logs— se informa como `no_matching_focus_sequencer_execution`.

## Diagnósticos

La consola está pensada para revisión rápida durante la operación:

- Muestra los errores clasificados como accionables.
- Muestra el total de warnings, sin imprimir cada warning individualmente.
- Muestra el total de errores visibles y los registros fatales.
- Conserva todos los diagnósticos, incluidos warnings, eventos esperados y detalles duplicados, en el informe JSON.

Entre los eventos normalmente suprimidos de la consola están los drivers opcionales no instalados, propiedades ASCOM no implementadas, cancelaciones esperadas de captura durante un meridian flip y mensajes de errores ignorados explícitamente por una secuencia.

Dos ejemplos de errores accionables son:

- `autofocus_no_solution`: SharpCap no encontró una posición de mejor foco dentro del rango explorado.
- `focuser_connection`: el monitor ASCOM del enfocador informó una desconexión.

## Archivos generados

| Archivo | Contenido |
|---|---|
| `sharpcap_session_report_*.json` | Informe completo y estructurado de la sesión, incluidas métricas, correcciones y diagnósticos. |
| `sharpcap_focus_corrections_*.csv` | Tabla de correcciones térmicas para filtrado y análisis en una hoja de cálculo. |
| `sharpcap_focus_corrections_*.txt` | Tabla legible de correcciones térmicas. |

## Limitaciones

- El analizador interpreta formatos concretos de logs de SharpCap y Focus Sequencer; cambios de versión o de scripts pueden requerir ajustes de patrones.
- La ausencia de telemetría en una ejecución no implica necesariamente un fallo de foco: puede indicar que el log no contiene el formato esperado o que no se pudo correlacionar una ejecución.
- Los diagnósticos se clasifican por patrones conocidos. Consulta el JSON ante una incidencia inesperada o para revisar los warnings completos.

## Licencia

Consulta [LICENSE](LICENSE).
