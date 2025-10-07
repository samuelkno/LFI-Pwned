<?php
// Nivel 5 - Requiere URL-encoded payload
// El objetivo: la aplicación solo decodifica y hace include() si el parámetro está URL-encoded.
// Requiere haber completado level4.

$progress_file = __DIR__ . '/../progress.json';
$has_access = false;
if (file_exists($progress_file)) {
    $p = json_decode(@file_get_contents($progress_file), true);
    if (is_array($p) && isset($p['level4']) && $p['level4'] === true) {
        $has_access = true;
    }
}

if (!$has_access) {
    ?><!doctype html>
    <html lang="es">
    <head><meta charset="utf-8"><title>Nivel 5 — Bloqueado</title><link rel="stylesheet" href="/assets/style.css"></head>
    <body>
      <main class="container">
        <header><h1>Nivel 5 — Bloqueado</h1></header>
        <section class="card">
          <p>Debes completar <strong>Nivel 4</strong> antes de intentar este nivel.</p>
          <p><a class="btn" href="/nivel4/">Ir a Nivel 4</a></p>
        </section>
      </main>
    </body>
    </html><?php
    exit;
}

// Lectura del parámetro
$param = isset($_GET['language']) ? $_GET['language'] : '';
$param = trim($param);
$decoded = '';
$error = '';
$content = '';

// Reglas: rechazamos entradas que NO contengan percent-encoding (ej: %2e)
// Esto fuerza al alumno a URL-encodear su payload.
if ($param === '') {
    $error = "Provee un payload URL-encoded en el parámetro 'language' (ej: %2e%2e%2f%2e%2e%2fetc%2fpasswd).";
} elseif (strpos($param, '%') === false) {
    $error = "Entrada inválida: el payload debe estar URL-encoded. Ejemplo: %2e%2e%2f%2e%2e%2fetc%2fpasswd";
} else {
    // Decodificamos usando rawurldecode para preservar + vs %20 etc.
    $decoded = rawurldecode($param);

    // DEBUG (comentario HTML) para que el alumno vea qué se intentó incluir:
    $debug_comment = "<!-- decoded_include_target = " . htmlspecialchars($decoded) . " -->";

    // Intentamos incluir la ruta decodificada (vulnerable intencionalmente)
    ob_start();
    @include($decoded);
    $content = ob_get_clean();
}

// Función para marcar progreso (silenciosa)
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
  <title>Nivel 5 — URL Encoding</title>
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
  <?php if (!empty($debug_comment)) echo $debug_comment; ?>
  <main class="container">
    <header><h1>Nivel 5 — Codificación (URL-encoded)</h1>
      <p>Este nivel solo acepta payloads URL-encoded y decodifica antes de incluir.</p>
    </header>

    <section class="card">
      <form method="get" action="">
        <label>Parámetro <code>language</code> (URL-encoded):</label><br>
        <input name="language" style="width:100%;padding:8px;margin-top:6px" value="<?php echo htmlspecialchars($param); ?>">
        <div style="margin-top:8px"><button class="btn" type="submit">Incluir (decodificar)</button><a class="btn" href="/nivel5/">Reset</a></div>
      </form>

      <hr>
      <?php if ($error !== ''): ?>
        <div style="color:#ffd2c2;background:#2e0b0b;padding:10px;border-radius:6px"><?php echo htmlspecialchars($error); ?></div>
      <?php endif; ?>

      <h3>Salida (preformatada):</h3>
      <pre><?php echo htmlspecialchars($content); ?></pre>

      <?php
      // Si se leyó /etc/passwd, marcar progreso y mostrar flag
      if (strpos($content, 'root:') !== false || strpos($decoded, '/etc/passwd') !== false) {
          $flagpath = __DIR__ . '/../flags/level5.txt';
          if (file_exists($flagpath)) {
              $flag = trim(file_get_contents($flagpath));
              echo "<div class='flag'>¡Nivel 5 completado! Flag: ".htmlspecialchars($flag)."</div>";
          } else {
              echo "<div class='flag'>¡Nivel 5 completado! (no se encontró file de flag)</div>";
          }
          mark_progress('level5');
          echo "<p style='margin-top:10px;'><a class='btn' href='/nivel6/'>Ir a Nivel 6</a></p>";
      }
      ?>
      <p class="muted" style="margin-top:12px">Ejemplos de payloads (usa el campo tal cual, ya codificados):</p>
      <pre class="muted" style="font-size:0.9rem">
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2fetc%2fpasswd
php%3A%2F%2Ffilter%2Fread%3Dconvert.base64-encode%2Fresource%3Detc%2Fpasswd
      </pre>
    </section>
  </main>
</body>
</html>
