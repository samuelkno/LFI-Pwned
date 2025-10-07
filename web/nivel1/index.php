<?php
// Nivel 1 - LFI básico (modificado para registrar progreso y avisar si no existe el recurso)
// WARNING: intentionally vulnerable - do not expose publicly

$default = 'languages/es.php';
$param = isset($_GET['language']) ? $_GET['language'] : 'es.php';

// Para facilitar la práctica mostramos exactamente qué se intenta incluir
$to_include = $param;

// Evitamos tratar como ruta relativa si viene vacío
if (trim($to_include) === '') {
    $to_include = $default;
}

// --- Determinar si el recurso existe (varias comprobaciones) ---
// Si es un wrapper (contiene '://') lo tratamos como recurso especial y no comprobamos con file_exists
$is_wrapper = (strpos($to_include, '://') !== false);
$found_path = false;
$path_to_include = $to_include;

if ($is_wrapper) {
    // si es wrapper (php://, data:, phar://, etc.) asumimos intento de recurso y permitimos la inclusión
    $found_path = true;
    $path_to_include = $to_include; // incluir tal cual
} else {
    // candidatos a comprobar (en este orden)
    $candidates = array(
        $to_include,
        __DIR__ . '/' . $to_include,
        __DIR__ . '/languages/' . $to_include,
        // si el usuario puso 'es' o 'en' sin .php, también probar con .php
        $to_include . '.php',
        __DIR__ . '/' . $to_include . '.php',
        __DIR__ . '/languages/' . $to_include . '.php',
    );

    foreach ($candidates as $c) {
        if (@file_exists($c)) {
            $found_path = true;
            $path_to_include = $c;
            break;
        }
    }
}

// Usamos @ to suppress warnings for the lab (so students see the output)
// Solo intentamos incluir si encontramos el recurso (o si es wrapper)
$content = '';
$not_found_message = '';
if ($found_path) {
    ob_start();
    @include($path_to_include);
    $content = ob_get_clean();
    // Si la inclusión produjo salida vacía y el archivo existe pero está vacío, lo consideramos "sin salida"
    // eso ya se muestra en $content (vacio). No lo tratamos como "no existe".
} else {
    // No se encontró ninguna ruta candidata válida
    $not_found_message = "El valor que colocaste no existe o no se encontró el recurso solicitado.";
}

// --- mark_progress function (igual que antes) ---
function mark_progress($level) {
    $pfile = __DIR__ . '/../progress.json';
    $prog = array();
    if (file_exists($pfile)) {
        $raw = @file_get_contents($pfile);
        $decoded = @json_decode($raw, true);
        if (is_array($decoded)) $prog = $decoded;
    }
    $prog[$level] = true;
    @file_put_contents($pfile, json_encode($prog, JSON_PRETTY_PRINT));
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

      <?php if ($not_found_message !== ''): ?>
        <div style="color:#fff;background:#6b1f1f;padding:10px;border-radius:6px;margin-bottom:10px">
          <?php echo htmlspecialchars($not_found_message); ?>
        </div>
      <?php endif; ?>

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
