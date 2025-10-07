<?php
// Nivel 2 - Path Traversal
// include("./languages/" . $_GET['language']);
// Este nivel exige haber completado Nivel 1 (chequea progress.json)

$progress_file = __DIR__ . '/../progress.json';
$has_access = false;
if (file_exists($progress_file)) {
    $p = json_decode(file_get_contents($progress_file), true);
    if (is_array($p) && isset($p['level1']) && $p['level1'] === true) {
        $has_access = true;
    }
}

if (!$has_access) {
    // Página con mensaje bloqueado
    ?><!doctype html>
    <html lang="es">
    <head>
      <meta charset="utf-8">
      <title>Nivel 2 — Bloqueado</title>
      <link rel="stylesheet" href="/assets/style.css">
    </head>
    <body>
      <main class="container">
        <header><h1>Nivel 2 — Bloqueado</h1></header>
        <section class="card">
          <p>Para intentar el Nivel 2 debes completar primero <strong>Nivel 1</strong>.</p>
          <p>Ve a <a class="btn" href="/nivel1/">Nivel 1</a> y encuentra la flag.</p>
        </section>
      </main>
    </body>
    </html><?php
    exit;
}

// Si llegó hasta aquí, puede intentar Level 2
$default = 'languages/es.php';
$param = isset($_GET['language']) ? $_GET['language'] : 'es.php';
$to_include = $param;
if (trim($to_include) === '') $to_include = $default;

ob_start();
@include("./languages/" . $to_include);
$content = ob_get_clean();

function mark_progress($level) {
    $pfile = __DIR__ . '/../progress.json';
    $prog = array();
    if (file_exists($pfile)) {
        $raw = file_get_contents($pfile);
        $decoded = json_decode($raw, true);
        if (is_array($decoded)) $prog = $decoded;
    }
    $prog[$level] = true;
    file_put_contents($pfile, json_encode($prog, JSON_PRETTY_PRINT));
}
?>
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>Nivel 2 — Path Traversal</title>
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
  <main class="container">
    <header><h1>Nivel 2 — Path Traversal</h1>
      <p>Vulnerabilidad (simulada): <code>include("./languages/" . $_GET['language']);</code></p>
    </header>

    <section class="card">
      <form method="get" action="">
        <label>Archivo a incluir (ej: ../../../../../../etc/passwd):</label><br>
        <input name="language" style="width:100%;padding:8px;margin-top:6px" value="<?php echo htmlspecialchars($param); ?>">
        <div style="margin-top:8px">
          <button class="btn" type="submit">Incluir</button>
          <a class="btn" href="/nivel2/">Reset</a>
        </div>
      </form>

      <hr>
      <h3>Salida (preformatada):</h3>
      <pre><?php echo htmlspecialchars($content); ?></pre>

      <?php
      // Si se logra leer /etc/passwd (o aparece root:), marcar progreso y mostrar flag
      if (strpos($content, 'root:') !== false || strpos($to_include, '/etc/passwd') !== false) {
          $flagpath = __DIR__ . '/../flags/level2.txt';
          if (file_exists($flagpath)) {
              $flag = trim(file_get_contents($flagpath));
              echo "<div class='flag'>¡Nivel 2 completado! Flag: ".htmlspecialchars($flag)."</div>";
          } else {
              echo "<div class='flag'>¡Nivel 2 completado! (no se encontró file de flag)</div>";
          }
          mark_progress('level2');
          echo "<p style='margin-top:10px;'><a class='btn' href='/nivel3/'>Ir a Nivel 3</a></p>";
      }
      ?>
    </section>
  </main>
</body>
</html>
