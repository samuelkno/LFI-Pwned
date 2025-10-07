<?php
// Nivel 1 - LFI básico (modificado para registrar progreso)
// WARNING: intentionally vulnerable - do not expose publicly

$default = 'languages/es.php';
$param = isset($_GET['language']) ? $_GET['language'] : 'es.php';

// Para facilitar la práctica mostramos exactamente qué se intenta incluir
$to_include = $param;

// Evitamos tratar como ruta relativa si viene vacío
if (trim($to_include) === '') {
    $to_include = $default;
}

// Usamos @ to suppress warnings for the lab (so students see the output)
ob_start();
@include($to_include);
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
  <title>Nivel 1 — LFI básico</title>
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
  <main class="container">
    <header>
      <h1>Nivel 1 — LFI básico</h1>
      <p>Parametro vulnerable: <code>?language=...</code></p>
    </header>

    <section class="card">
      <form method="get" action="">
        <label>Archivo a incluir:</label><br>
        <input name="language" style="width:100%;padding:8px;margin-top:6px" value="<?php echo htmlspecialchars($param); ?>">
        <div style="margin-top:8px">
          <button class="btn" type="submit">Incluir</button>
          <a class="btn" href="/nivel1/">Reset</a>
        </div>
      </form>

      <hr>
      <h3>Salida (preformatada):</h3>
      <pre><?php echo htmlspecialchars($content); ?></pre>

      <?php
      // Lógica simple para mostrar "victoria" (flag) cuando se logra leer /etc/passwd
      if (strpos($content, 'root:') !== false || $to_include === '/etc/passwd') {
          // Leer flag desde archivo en /var/www/html/flags/level1.txt si existe
          $flagpath = __DIR__ . '/../flags/level1.txt';
          if (file_exists($flagpath)) {
              $flag = trim(file_get_contents($flagpath));
              echo "<div class='flag'>¡Nivel 1 completado! Flag: ".htmlspecialchars($flag)."</div>";
          } else {
              echo "<div class='flag'>¡Nivel 1 completado! (no se encontró file de flag)</div>";
          }

          // Registrar progreso para desbloquear Nivel 2
          mark_progress('level1');

          // Mostrar enlace de navegación hacia nivel 2 (aunque nivel2 chequeará progreso también)
          echo "<p style='margin-top:10px;'><a class='btn' href='/nivel2/'>Ir a Nivel 2</a></p>";
      }
      ?>
    </section>
  </main>
</body>
</html>
