<?php
// create_phar.php - crea example.phar en /var/www/html con welcome.php dentro
// Ejecutar: php web/nivel6/create_phar.php  (desde la raíz del proyecto dentro del contenedor)

$pharFile = __DIR__ . '/../../example.phar'; // será /var/www/html/example.phar
$sourceFile = __DIR__ . '/welcome.php';     // web/nivel6/welcome.php

if (!file_exists($sourceFile)) {
    echo "Error: no encuentro $sourceFile\n";
    exit(1);
}

// eliminar phar viejo si existe
if (file_exists($pharFile)) {
    @unlink($pharFile);
}

try {
    // Crear phar (asegúrate que phar.readonly = Off en la configuración si falla)
    $p = new Phar($pharFile);
    $p->startBuffering();

    // Añadir file con nombre welcome.php en la raíz del phar
    $p->addFile($sourceFile, 'welcome.php');

    // Opcional: añadir stub mínimo para permitir ejecución directa (no necesario para lectura)
    $p->setStub($p->createDefaultStub('welcome.php'));

    $p->stopBuffering();

    echo "Phar creado en: $pharFile\n";
    echo "Contenido:\n";
    foreach (new RecursiveIteratorIterator($p) as $file) {
        echo " - " . $file . "\n";
    }
} catch (Exception $e) {
    echo "Fallo al crear phar: " . $e->getMessage() . "\n";
    echo "Si aparece 'phar.readonly' activo, ejecuta PHP con phar.readonly=0 o modifica php.ini (solo en laboratorio).\n";
    exit(1);
}
