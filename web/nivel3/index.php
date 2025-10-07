<?php
// Nivel 3 - Prefijo de nombre
// Vulnerabilidad demostrativa: include("lang_" . $_GET['language']);
// Requiere haber completado level2 (ver progress.json)

// --- Comprueba progreso ---
$progress_file = __DIR__ . '/../progress.json';
$has_access = false;
if (file_exists($progress_file)) {
    $p = json_decode(@file_get_contents($progress_file), true);
    if (is_array($p) && isset($p['level2']) && $p['level2'] === true) {
        $has_access = true;
    }
}

if (!$has_access) {
    ?><!doctype html>
    <html lang="es">
    <head>
      <meta charset="utf-8">
      <title>Nivel 3 — Bloqueado</title>
      <link rel="stylesheet" href="/assets/style.css">
    </head>
    <body>
      <main class="container">
        <header><h1>Nivel 3 — Bloqueado</h1></header>
        <section class="card">
          <p>Primero completa <strong>Nivel 2</strong>.</p>
          <p><a class="btn" href="/nivel2/">Ir a Nivel 2</a></p>
        </section>
      </main>
    </body>
    </html><?php
    exit;
}

// --- Si tiene acceso, procesa la inclusión vulnerable ---
$default = 'es.php';
$param = isset($_GET['language']) ? $_GET['language'] : $default;
$to_include_raw = trim($param) === '' ? $default : $param;

// Construimos exactamente como en el reto: "lang_" . $_GET['language']
$include_target = "lang_" . $to_include_raw;

// Capturamos la salida del include (y suprimimos warnings)
ob_start();
@include($include_target);
$content = ob_get_clean();

// Función segura para marcar progreso (no muestra warnings)
function mark_progress($level) {
    $pfile = __DIR__ . '/../progress.json';
    $prog = array();
    if (file_exists($pfile)) {
        $raw = @file_get_contents($pfile);
        $decoded = @json_decode($raw, true);
        if (is_array($decoded)) $prog = $decoded;
    }
    $prog[$level] = true;

    // Intentar escribir solo si parece posible (evitar warnings visibles)
    $dir = dirname($pfile);
    if ((is_dir($dir) && is_writable($dir)) || (file_exists($pfile) && is_writable($pfile))) {
        @file_put_contents($pfile, json_encode($prog, JSON_PRETTY_PRINT));
    } else {
        // Registrar en /tmp para debug de laboratorio (silencioso en la web)
        @file_put_contents('/tmp/lfi_lab_progress_error.log', date('[Y-m-d H:i]') . " no se pudo escribir $pfile\n", FILE_APPEND);
    }
}
?>
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>Nivel 3 — Prefijo de nombre</title>
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
  <main class="container">
    <header><h1>Nivel 3 — Prefijo de nombre</h1>
      <p>Vulnerabilidad (simulada): <code>include("lang_" . $_GET['language']);</code></p>
    </header>

    <section class="card">
      <form method="get" action="">
        <label>Parámetro <code>language</code> (ej: <code>/../../../../etc/passwd</code>):</label><br>
        <input name="language" style="width:100%;padding:8px;margin-top:6px" value="<?php echo htmlspecialchars($param); ?>">
        <div style="margin-top:8px">
          <button class="btn" type="submit">Incluir</button>
          <a class="btn" href="/nivel3/">Reset</a>
        </div>
      </form>

      <hr>
      <h3>Salida (preformatada):</h3>
      <pre><?php echo htmlspecialchars($content); ?></pre>

      <?php
      // Si aparece 'root:' en la salida (o si el parámetro apunta explícitamente a /etc/passwd),
      // marcar progreso y mostrar flag.
      if (strpos($content, 'root:') !== false || strpos($include_target, '/etc/passwd') !== false) {
          $flagpath = __DIR__ . '/../flags/level3.txt';
          if (file_exists($flagpath)) {
              $flag = trim(file_get_contents($flagpath));
              echo "<div class='flag'>¡Nivel 3 completado! Flag: ".htmlspecialchars($flag)."</div>";
          } else {
              echo "<div class='flag'>¡Nivel 3 completado! (no se encontró file de flag)</div>";
          }
          mark_progress('level3');
          echo "<p style='margin-top:10px;'><a class='btn' href='/nivel4/'>Ir a Nivel 4</a></p>";
      }
      ?>
    </section>
  </main>
</body>
</html>
