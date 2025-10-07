<?php
// Nivel 4 - Filtros transversales no recursivos
// Mitigación: $language = str_replace('../', '', $_GET['language']);
// Bypass: usar '....//....//....//' (cada '....//' equivale a '../' tras normalización)

// --- Comprueba progreso (necesita level3) ---
$progress_file = __DIR__ . '/../progress.json';
$has_access = false;
if (file_exists($progress_file)) {
    $p = json_decode(@file_get_contents($progress_file), true);
    if (is_array($p) && isset($p['level3']) && $p['level3'] === true) {
        $has_access = true;
    }
}

if (!$has_access) {
    ?><!doctype html>
    <html lang="es">
    <head><meta charset="utf-8"><title>Nivel 4 — Bloqueado</title><link rel="stylesheet" href="/assets/style.css"></head>
    <body>
      <main class="container">
        <header><h1>Nivel 4 — Bloqueado</h1></header>
        <section class="card">
          <p>Debes completar <strong>Nivel 3</strong> antes de intentar este nivel.</p>
          <p><a class="btn" href="/nivel3/">Ir a Nivel 3</a></p>
        </section>
      </main>
    </body>
    </html><?php
    exit;
}

// --- Procesamiento vulnerable (mitigación no recursiva) ---
$param = isset($_GET['language']) ? $_GET['language'] : 'es.php';
$param = trim($param);

// Simulamos la mitigación vulnerable común (reemplaza las ocurrencias exactas "../")
$filtered = str_replace('../', '', $param);

// Construimos la ruta a incluir — por ejemplo el código hace include($filtered);
$to_include = $filtered;

// Para que los estudiantes vean qué cadena se intenta incluir (comentario HTML)
// útil para depuración sin mostrar errores del servidor
$debug_comment = "<!-- include_target = " . htmlspecialchars($to_include) . " -->";

// Incluimos (suprimimos warnings para que no salgan errores técnicos)
ob_start();
@include($to_include);
$content = ob_get_clean();

// Función para marcar progreso de forma silenciosa
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
  <title>Nivel 4 — Filtros no recursivos</title>
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
  <?php echo $debug_comment; /* comentario HTML para ver include_target en la fuente */ ?>
  <main class="container">
    <header><h1>Nivel 4 — Filtros transversales no recursivos</h1>
      <p>Mitigación: <code>$language = str_replace('../', '', $_GET['language']);</code></p>
    </header>

    <section class="card">
      <form method="get" action="">
        <label>Parámetro <code>language</code> (ej: <code>....//....//....//etc/passwd</code>):</label><br>
        <input name="language" style="width:100%;padding:8px;margin-top:6px" value="<?php echo htmlspecialchars($param); ?>">
        <div style="margin-top:8px"><button class="btn" type="submit">Incluir</button><a class="btn" href="/nivel4/">Reset</a></div>
      </form>

      <hr>
      <h3>Salida (preformatada):</h3>
      <pre><?php echo htmlspecialchars($content); ?></pre>

      <?php
      // Detecta si se leyó /etc/passwd (o aparece 'root:') y marca progreso
      if (strpos($content, 'root:') !== false || strpos($to_include, '/etc/passwd') !== false) {
          $flagpath = __DIR__ . '/../flags/level4.txt';
          if (file_exists($flagpath)) {
              $flag = trim(file_get_contents($flagpath));
              echo "<div class='flag'>¡Nivel 4 completado! Flag: ".htmlspecialchars($flag)."</div>";
          } else {
              echo "<div class='flag'>¡Nivel 4 completado! (no se encontró file de flag)</div>";
          }
          mark_progress('level4');
          echo "<p style='margin-top:10px;'><a class='btn' href='/nivel5/'>Ir a Nivel 5</a></p>";
      }
      ?>
      <p class="muted" style="margin-top:12px">Tip: mira el código fuente de la página (Ctrl+U) para ver el <code>include_target</code> que intenta incluir.</p>
    </section>
  </main>
</body>
</html>
