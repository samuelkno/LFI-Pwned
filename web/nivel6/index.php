<?php
// Nivel 6 - Wrappers PHP (php://filter, data://, phar://, zip://, compress.zlib://, ...)
// El objetivo: mostrar técnicas para leer el código fuente usando wrappers.
// Requiere haber completado level5.

// --- Comprueba progreso (necesita level5) ---
$progress_file = __DIR__ . '/../progress.json';
$has_access = false;
if (file_exists($progress_file)) {
    $p = json_decode(@file_get_contents($progress_file), true);
    if (is_array($p) && isset($p['level5']) && $p['level5'] === true) {
        $has_access = true;
    }
}

if (!$has_access) {
    ?><!doctype html>
    <html lang="es">
    <head><meta charset="utf-8"><title>Nivel 6 — Bloqueado</title><link rel="stylesheet" href="/assets/style.css"></head>
    <body>
      <main class="container">
        <header><h1>Nivel 6 — Bloqueado</h1></header>
        <section class="card">
          <p>Debes completar <strong>Nivel 5</strong> antes de intentar este nivel.</p>
          <p><a class="btn" href="/nivel5/">Ir a Nivel 5</a></p>
        </section>
      </main>
    </body>
    </html><?php
    exit;
}

// --- Lectura del parámetro ---
$param_raw = isset($_GET['language']) ? trim($_GET['language']) : '';
$error = '';
$content = '';
$debug_comment = '';

// Si está vacío mostramos la ayuda
if ($param_raw === '') {
    $error = "Provee el parámetro 'language'. Ejemplos en la sección de ayuda abajo.";
} else {
    // Decidir si añadir ".php" o no:
    // - si el parámetro comienza con un wrapper conocido (contiene '://') NO añadimos .php (se espera que el wrapper incluya resource=...)
    // - si no contiene '://' añadimos '.php' para simular include(\$_GET['language'] . '.php')
    $need_append_php = (strpos($param_raw, '://') === false);
    if ($need_append_php) {
        $include_target = $param_raw . '.php';
    } else {
        // Mantener exactamente lo que el usuario pasó (ej: php://filter/.../resource=welcome)
        $include_target = $param_raw;
        // Si el wrapper es php://filter y el resource no termina en .php, dejamos que el alumno use resource=welcome (se transformará en welcome.php si lo codifican apropiadamente)
        // Nota: muchos ejemplos funcionarán pasando resource=welcome (sin .php) porque el include final en la práctica puede referenciar welcome.php si la ruta lo indica.
    }

    // Mostrar en fuente HTML (comentario) el target exacto
    $debug_comment = "<!-- include_target = " . htmlspecialchars($include_target) . " -->";

    // Intento de inclusión (suprimir warnings)
    ob_start();
    @include($include_target);
    $raw_out = ob_get_clean();

    // Si la salida parece base64 (por php://filter) la decodificamos para mostrar el código fuente de manera legible
    $is_base64 = false;
    // heurística: sólo si la salida es base64 válida y relativamente larga
    if ($raw_out !== '' && preg_match('#^[A-Za-z0-9+/=\s]+$#', trim($raw_out))) {
        $maybe = preg_replace('/\s+/', '', $raw_out);
        // decodificar tentativamente
        $decoded = base64_decode($maybe, true);
        if ($decoded !== false && strlen($decoded) > 10) {
            $is_base64 = true;
            $content = $decoded;
        }
    }

    // Si no era base64, pero vino como data:// (p. ej. data:text/plain;base64,...), intentar manejarlo
    if (!$is_base64 && $raw_out !== '') {
        $content = $raw_out;
    }

    // Algunos wrappers devuelven la salida en formato no textual; mostramos igualmente la representación
    if ($content === '' && $raw_out !== '') {
        $content = $raw_out;
    }
}

// Función para marcar progreso (silenciosa si no puede escribir)
function mark_progress($level) {
    $pfile = __DIR__ . '/../progress.json';
    $prog = array();
    if (file_exists($pfile)) {
        $raw = @file_get_contents($pfile);
        $decoded = @json_decode($raw, true);
        if (is_array($decoded)) $prog = $decoded;
    }
    $prog[$level] = true;
    $dir = dirname($pfile);
    if ((is_dir($dir) && is_writable($dir)) || (file_exists($pfile) && is_writable($pfile))) {
        @file_put_contents($pfile, json_encode($prog, JSON_PRETTY_PRINT));
    } else {
        @file_put_contents('/tmp/lfi_lab_progress_error.log', date('[Y-m-d H:i]') . " no se pudo escribir $pfile\n", FILE_APPEND);
    }
}
?>
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>Nivel 6 — Wrappers PHP</title>
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
  <?php if (!empty($debug_comment)) echo $debug_comment; ?>
  <main class="container">
    <header>
      <h1>Nivel 6 — Wrappers PHP</h1>
      <p>Incluye usando <code>include($_GET['language'] . ".php")</code> (simulado). Aprende a usar wrappers para ver código fuente.</p>
    </header>

    <section class="card">
      <form method="get" action="">
        <label>Parámetro <code>language</code> (ejemplos abajo):</label><br>
        <input name="language" style="width:100%;padding:8px;margin-top:6px" value="<?php echo htmlspecialchars($param_raw); ?>">
        <div style="margin-top:8px"><button class="btn" type="submit">Incluir</button><a class="btn" href="/nivel6/">Reset</a></div>
      </form>

      <hr>
      <?php if ($error !== ''): ?>
        <div style="color:#ffd2c2;background:#2e0b0b;padding:10px;border-radius:6px"><?php echo htmlspecialchars($error); ?></div>
      <?php endif; ?>

      <h3>Salida (preformatada):</h3>
      <pre><?php echo htmlspecialchars($content); ?></pre>

      <?php
      // Si detectamos root: o la flag en la salida, marcamos progreso
      $detected = false;
      if (strpos($content, 'root:') !== false) $detected = true;
      $flagpath = __DIR__ . '/../flags/level6.txt';
      if (!$detected && file_exists($flagpath)) {
          $flagtxt = trim(file_get_contents($flagpath));
          if (strpos($content, $flagtxt) !== false) $detected = true;
      }
      if ($detected) {
          if (file_exists($flagpath)) {
              $flag = trim(file_get_contents($flagpath));
              echo "<div class='flag'>¡Nivel 6 completado! Flag: ".htmlspecialchars($flag)."</div>";
          } else {
              echo "<div class='flag'>¡Nivel 6 completado! (no se encontró file de flag)</div>";
          }
          mark_progress('level6');
      }
      ?>

      <hr>
      <h4>Wrappers / payloads de ejemplo</h4>
      <p>Algunos payloads que funcionan según la implementación y archivos disponibles:</p>
      <ul>
        <li><code>php://filter/read=convert.base64-encode/resource=welcome</code>
            — incluye <code>welcome.php</code> pero devuelve base64; la página decodifica y muestra el código fuente.</li>
        <li><code>php://filter/read=convert.base64-encode/resource=nivel6/archivo</code>
            — apunta a otro archivo dentro del nivel (ajusta la ruta si hace falta).</li>
        <li><code>data:text/plain;base64,PD9waHAgZWNobyAnSG9sYSc7ID8=</code>
            — incluye contenido inline (data URI). Si usas data:// no se añade .php automáticamente.</li>
        <li><code>phar:///var/www/html/some.phar#file_inside</code>
            — si hay phar/zip creado en el FS se puede leer el archivo dentro del phar.</li>
        <li><code>zip:///var/www/html/some.zip#file.php</code>
            — similar a phar (si existe el zip en el FS).</li>
        <li><code>compress.zlib:///var/www/html/file.gz</code> — intenta incluir archivo comprimido.</li>
      </ul>

      <p class="muted">Consejo: abre el código fuente (Ctrl+U) y busca el comentario <code>include_target</code> para ver exactamente qué intenta incluir el servidor. Ajusta la ruta del payload si es necesario (p. ej. usar resource=welcome vs resource=welcome.php según cómo montes archivos).</p>

      <h4>Ejemplos concretos que puedes pegar en el campo (uno por uno)</h4>
      <pre class="muted" style="font-size:0.9rem">
php://filter/read=convert.base64-encode/resource=welcome
php://filter/read=convert.base64-encode/resource=nivel6/welcome
data:text/plain;base64,PD9waHAKZWNobyAnHola desde data URI';ID8+
phar:///var/www/html/example.phar#welcome.php
zip:///var/www/html/example.zip#welcome.php
      </pre>
      <p class="muted">Si el payload no funciona, mira el comentario HTML (include_target) en la fuente y ajusta el nombre del recurso (quizá necesites añadir subdirectorios o .php).</p>
    </section>
  </main>
</body>
</html>
