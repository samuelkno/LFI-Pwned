<?php
?><!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Laboratorio LFI — Inicio</title>
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
  <main class="container">
    <header>
      <h1>Laboratorio LFI</h1>
      <p>Entorno controlado para practicar Local File Inclusion (LFI). Usa solo en laboratorio local.</p>
    </header>

    <section class="cards">
      <article class="card">
        <h2>Nivel 1 — LFI Básico</h2>
        <p>Inclusión simple basada en parámetro `language`.</p>
        <a class="btn" href="/nivel1/">Abrir Nivel 1</a>
      </article>

      <article class="card locked">
        <h2>Niveles posteriores</h2>
        <p>Path traversal, prefijos, filtros, encoding y php://filters.</p>
        <p class="muted">(Bloqueados hasta completar niveles anteriores)</p>
      </article>
    </section>

    <footer>
      <p>Profesor: laboratorio hecho por Sackno — Mantener en entorno aislado</p>
    </footer>
  </main>
</body>
</html>

